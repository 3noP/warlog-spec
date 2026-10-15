"""Content scan verdict — a portable, signed record of what a guardrail saw.

A **scan verdict** is a signed statement that a piece of agent traffic was
examined by a named detector, what that detector found, and what the gateway
did about it. It is the artifact an operator hands to an auditor, a regulator
or an insurer to answer *"you say your guardrail runs — show me"* without
handing over the traffic itself.

Like :mod:`warlog_spec.a2a`, this module is the **open-source verification
primitive**: the schema plus the pure ``sign`` / ``verify`` functions are
Apache-2.0. What decides whether a finding becomes a refusal, which detector
runs, and what a tenant's posture is, lives in the commercial gateway and NOT
here.

Design (RFC-0006):

- **A sibling of** :class:`~warlog_spec.a2a.A2AAttestation`, **not an**
  :class:`~warlog_spec.provider_abi.AuditRow`. An audit row requires an
  ``action_id`` from a closed enum, a ``subject``, a ``phase``, a ``connector``
  and an ``idempotency_key``; a verdict has none of those, and widening the
  action enum to admit one would corrupt the type that carries the platform's
  action semantics. Same reasoning that RFC-0005 used to reject folding
  ``A2ASignature`` into ``AuditAttestation``.
- **The content is bound, never carried.** ``content_binding`` is a
  domain-separated sha256 of what was scanned. A verifier holding the original
  payload can prove the verdict applies to it; a verifier without it learns
  nothing. This is what makes a verdict publishable: a record that quoted the
  matched bytes would be a leak of exactly the secret it flagged.
- **The gateway signs; the detector is named.** A detector produces a finding,
  it does not decide an outcome, so a signature by the detector could not
  legitimately cover ``disposition``. The signer is the enforcement point, and
  the sentence the signature makes true is: *my detector D at version V, over
  this content, reported F, and I observed / refused it.*
- **The verdict joins the attestation on the same ``request_binding``.** When
  the scanned call carried an A2A attestation, both documents carry the byte
  value computed by :func:`~warlog_spec.a2a.compute_request_binding`. Two
  independent signatures then provably describe one call. Absent an
  attestation the field is ``None``, which is a fact about the caller, not a
  gap in the record.

**No floats in the canonical bytes, and that is not a style choice.**
``json.dumps(1.0)`` is ``"1.0"`` in Python and ``JSON.stringify(1.0)`` is
``"1"`` in JavaScript. A score of exactly 1.0 or 0.0 — the two a classifier
reaches most often at its extremes — would therefore produce different
canonical bytes on the two sides, and the signature would fail in a way
indistinguishable from tampering. The A2A payload has no numeric field, which
is why the spec has never met this. Scores and thresholds are carried as
integer thousandths (``score_milli=873`` is 0.873), which both languages
serialise identically and which is more precision than a guardrail score
honestly has.

Two deliberate differences from A2A verification, both consequences of a
verdict being a **record** rather than a **capability**:

- There is **no freshness window**. An attestation that is too old must be
  refused because presenting it authorises something. A verdict from last year
  is simply last year's verdict; rejecting it on age would destroy the only
  thing it is for.
- There is **no audience**. A verdict is not minted for a recipient, so there
  is nothing to bind and nothing an attacker gains by showing it elsewhere.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from warlog_spec._base import SpecModel
# One exception type for one situation. `A2ACryptoUnavailable` names the
# package's missing optional extra, which is a fact about the install and not
# about A2A; a second near-identical class would leave callers writing
# `except (A2ACryptoUnavailable, ScanVerdictCryptoUnavailable)` to catch it.
from warlog_spec.a2a import A2ACryptoUnavailable
from warlog_spec.audit_chain import canonical_json_bytes
from warlog_spec.provider_abi import HEX64_PATTERN, HEX_PATTERN

SCAN_VERDICT_VERSION = "1.0"

#: Domain-separation prefix for the signed bytes. Ends with ``"|"``; the
#: canonical payload (a JSON object starting with ``{``) follows at a fixed
#: position, so no string field inside the payload can forge the prefix. A
#: scan-verdict signature can therefore never be replayed as an audit-chain or
#: A2A signature, nor the reverse.
_SCAN_VERDICT_DOMAIN = b"warlog-spec/v1/scan-verdict|"

#: Domain-separation prefix for :func:`compute_content_binding`. Separate from
#: the signing domain on purpose: one covers a payload, the other covers raw
#: scanned text, and a single prefix would let a crafted payload be presented
#: as a content binding.
_SCAN_CONTENT_DOMAIN = b"warlog-spec/v1/scan-content|"

#: Where in the agent's traffic the scanned bytes came from.
#:
#: ``mcp_tool_manifest`` is the one entry that is not a message in a
#: conversation: it is the server's advertised capability, the tool descriptions
#: a model reads as trusted context, and it is where Tool Poisoning lives
#: because the payload is metadata rather than traffic. Its ``content`` for
#: :func:`compute_content_binding` is specified in RFC-0006 — the CANONICAL
#: tool-list bytes, not the raw frame, because MCP fixes neither the order of
#: the ``tools`` array nor the serialisation of each entry, and two proxies must
#: not produce two bindings for the same manifest.
ScanSurface = Literal[
    "llm_request",
    "llm_response",
    "mcp_tool_args",
    "mcp_tool_result",
    "mcp_resource_result",
    "mcp_tool_manifest",
]

#: Who produced the scanned bytes. The distinction is not cosmetic: an
#: injection found in a tool RESULT is a fact about the environment the agent
#: reads from, and holding the agent responsible for it would be the same
#: error as scoring an agent down for a vendor outage.
ScanDirection = Literal["egress", "ingress"]

#: What the gateway did with the finding. ``observed`` is a shadow-mode
#: recording that changed nothing about the call.
ScanDisposition = Literal["observed", "refused"]

#: What kind of statement the detector is able to make.
#:
#: ``deterministic`` — a rule engine. "Clean" means *no rule matched*, a
#: complete statement over its rule set, and there is no score to report.
#: ``model`` — a classifier. "Clean" means *below threshold*, a probabilistic
#: statement, and it MUST report the score and the threshold that produced it.
#:
#: Conflating the two is how a probabilistic "probably fine" gets read as a
#: guarantee. Deriving the difference from ``score is None`` would be a guess.
DetectorKind = Literal["deterministic", "model"]


class ScanVerdictError(Exception):
    """Raised when a scan verdict fails verification.

    Covers a bad signature and a ``content_binding`` that does not match the
    content the verifier holds. Callers SHOULD surface it as a refusal to
    accept the record, never as a silent pass.
    """


class ScanVerdictSignature(SpecModel):
    """Detached signature envelope for a :class:`ScanVerdictPayload`.

    A third sibling of :class:`~warlog_spec.provider_abi.AuditAttestation` and
    :class:`~warlog_spec.a2a.A2ASignature` rather than a shared base class, and
    that is deliberate. Each artifact owning its own wire type is what stops a
    change made for one from silently altering another's canonical bytes; a
    common base would couple three signature formats that must be free to
    diverge. RFC-0005 set this precedent for the same reason.
    """

    algorithm: Literal["Ed25519"] = Field(
        default="Ed25519",
        description="Signature algorithm. Ed25519 only in v1 (RFC-0004 asymmetric path).",
    )
    signature_value: str = Field(
        min_length=128,
        max_length=128,
        pattern=HEX_PATTERN,
        description=(
            "Hex-encoded Ed25519 signature over the domain-separated canonical "
            "payload bytes (64 bytes -> 128 hex)."
        ),
    )
    key_id: str = Field(
        min_length=1,
        description=(
            "Reference resolving to the Ed25519 public key of the GATEWAY that "
            "signed this verdict (RFC-0004 semantics). Not the detector's key: "
            "the detector reports, the enforcement point attests."
        ),
    )
    canonicalization_format: Literal["v1"] = Field(
        default="v1",
        description="Canonical-bytes format identifier, decoupled from the payload's spec_version.",
    )


class ScanVerdictPayload(SpecModel):
    """The signed claim: what was examined, by what, with what outcome."""

    verdict_id: str = Field(
        min_length=1,
        description=(
            "Stable identifier for this verdict. Present for identity, not for "
            "anti-replay: two identical findings on identical content would "
            "otherwise be byte-identical, and an operator could not tell one "
            "event from two."
        ),
    )
    tenant_ref: str = Field(
        min_length=1,
        description="Opaque tenant identifier the scanned traffic belonged to.",
    )
    agent_id: str | None = Field(
        default=None,
        description=(
            "Stable identity of the agent whose traffic was scanned, when it "
            "proved one. None means the caller was unattested, which is a fact "
            "about the call and not a missing field."
        ),
    )
    request_binding: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=HEX64_PATTERN,
        description=(
            "The A2A attestation's request_binding for the scanned call, when "
            "the call carried one. Identical bytes in both documents are what "
            "lets a verifier prove the verdict and the attestation describe the "
            "same request. Compute via warlog_spec.a2a.compute_request_binding."
        ),
    )
    surface: ScanSurface = Field(description="Where in the agent's traffic the bytes came from.")
    direction: ScanDirection = Field(
        description="egress = the agent produced it; ingress = the environment did.",
    )
    detector: str = Field(
        min_length=1,
        description="Name of the detector that produced the finding, e.g. 'regex_egress'.",
    )
    detector_version: str = Field(
        min_length=1,
        description=(
            "Version of that detector. Bumped whenever its rule set or weights "
            "change: a finding trend that crosses a silent version boundary is "
            "not a trend."
        ),
    )
    detector_kind: DetectorKind = Field(
        description="Whether 'clean' means no rule matched, or below a threshold.",
    )
    finding: str | None = Field(
        default=None,
        description=(
            "Category of what was found, e.g. 'secret.aws_access_key_id'. None "
            "means clean. NEVER the matched bytes, the offsets, or any excerpt: "
            "a record that quoted the secret it flagged would leak exactly what "
            "it exists to protect."
        ),
    )
    score_milli: int | None = Field(
        default=None,
        ge=0,
        le=1000,
        description=(
            "The model's score in thousandths (873 = 0.873), for a model "
            "detector. None for a deterministic one, because a rule that "
            "matched has no probability and writing 1000 would be a fabricated "
            "measurement on the surface that decides a refusal. Integer, not "
            "float: see the module docstring on canonical bytes."
        ),
    )
    threshold_milli: int | None = Field(
        default=None,
        ge=0,
        le=1000,
        description=(
            "The threshold the score was compared against, in thousandths. "
            "Meaningless without a score."
        ),
    )
    content_binding: str = Field(
        min_length=64,
        max_length=64,
        pattern=HEX64_PATTERN,
        description=(
            "sha256 hex binding this verdict to the exact bytes that were "
            "scanned, via compute_content_binding(). The content itself is "
            "never carried."
        ),
    )
    disposition: ScanDisposition = Field(
        description="What the gateway did: recorded it, or refused the call.",
    )
    scanned_at: datetime = Field(
        description="When the content was examined (aware UTC).",
    )

    @model_validator(mode="after")
    def _check_claim_coherence(self) -> ScanVerdictPayload:
        """Reject the combinations that would make the record dishonest.

        These are validation rules rather than documentation because each one
        describes a verdict a reader could reasonably misinterpret, and the
        wire format is the last place able to refuse it.
        """
        if self.detector_kind == "deterministic" and (
            self.score_milli is not None or self.threshold_milli is not None
        ):
            raise ValueError(
                "a deterministic detector cannot report a score or a threshold: "
                "a rule either matched or it did not"
            )
        if self.detector_kind == "model" and (
            self.score_milli is None or self.threshold_milli is None
        ):
            raise ValueError(
                "a model detector must report both its score and the threshold it "
                "was compared against, or its verdict cannot be re-derived"
            )
        if self.disposition == "refused" and self.finding is None:
            raise ValueError("a call cannot be refused on a clean verdict")
        return self


class ScanVerdict(SpecModel):
    """The full, signed verdict envelope."""

    spec_version: Literal["1.0"] = Field(default=SCAN_VERDICT_VERSION)
    payload: ScanVerdictPayload
    signature: ScanVerdictSignature


# =============================================================================
# Content binding + canonicalization (shared by signer and verifier)
# =============================================================================


def compute_content_binding(surface: str, content: str) -> str:
    """sha256 hex of ``domain || surface || "|" || content``.

    Binds a verdict to the exact bytes examined **without carrying them**. The
    surface is mixed in so a binding computed over a tool result can never be
    presented as one computed over a request body.

    Deliberately independent of the detector: two detectors scanning the same
    bytes produce the same binding, which is what lets their verdicts be
    correlated by a third party who holds neither.
    """
    binding_bytes = (
        _SCAN_CONTENT_DOMAIN + surface.encode("utf-8") + b"|" + content.encode("utf-8")
    )
    return hashlib.sha256(binding_bytes).hexdigest()


def canonicalize_scan_verdict_v1(payload: ScanVerdictPayload) -> bytes:
    """Domain-separated canonical bytes that the Ed25519 signature covers.

    ``_SCAN_VERDICT_DOMAIN`` + ``canonical_json_bytes(payload as camelCase JSON)``,
    byte-identical to the TypeScript ``canonicalizeScanVerdictV1``.
    """
    return _SCAN_VERDICT_DOMAIN + canonical_json_bytes(
        payload.model_dump(mode="json", by_alias=True)
    )


# =============================================================================
# Ed25519 sign / verify (optional 'crypto' extra)
# =============================================================================


def _load_crypto() -> tuple[Any, Any, Any]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover - only without the extra installed
        raise A2ACryptoUnavailable(
            "Scan verdict Ed25519 signing/verification requires the optional "
            "'cryptography' dependency. Install with: pip install warlog-spec[crypto]"
        ) from exc
    return InvalidSignature, Ed25519PrivateKey, Ed25519PublicKey


def sign_scan_verdict(
    payload: ScanVerdictPayload,
    *,
    private_key_pem: bytes,
    key_id: str,
) -> ScanVerdict:
    """Sign ``payload`` with the gateway's Ed25519 private key (PEM).

    The signer is the enforcement point, not the detector: ``disposition`` is
    the gateway's decision, and a signature that covered it on the detector's
    behalf would attest to something the detector never chose.
    """
    _inv, Ed25519PrivateKey, _pub = _load_crypto()
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ScanVerdictError("provided private key is not an Ed25519 key")

    signature_hex = key.sign(canonicalize_scan_verdict_v1(payload)).hex()
    return ScanVerdict(
        payload=payload,
        signature=ScanVerdictSignature(signature_value=signature_hex, key_id=key_id),
    )


def verify_scan_verdict(
    verdict: ScanVerdict,
    *,
    public_key_pem: bytes,
    expected_content: str | None = None,
) -> ScanVerdictPayload:
    """Verify a verdict and return its payload, or raise :class:`ScanVerdictError`.

    Two checks, and only two:

    1. The Ed25519 signature over the domain-separated canonical bytes.
    2. If ``expected_content`` is supplied, that ``content_binding`` was
       computed over exactly those bytes on this verdict's surface.

    ``expected_content`` is optional because the interesting case is the
    verifier who does **not** hold the traffic: an auditor can establish that a
    gateway signed this statement without ever being shown what was scanned.
    Passing the content upgrades that to proof the statement is about it.

    There is no freshness check and no audience check. A verdict is a record,
    not a capability: age does not weaken it and presenting it elsewhere gains
    an attacker nothing.
    """
    InvalidSignature, _priv, Ed25519PublicKey = _load_crypto()
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ScanVerdictError("resolved public key is not an Ed25519 key")
    try:
        key.verify(
            bytes.fromhex(verdict.signature.signature_value),
            canonicalize_scan_verdict_v1(verdict.payload),
        )
    except InvalidSignature as exc:
        raise ScanVerdictError("Ed25519 signature verification failed") from exc
    except ValueError as exc:
        raise ScanVerdictError("malformed signature encoding") from exc

    if expected_content is not None:
        expected = compute_content_binding(verdict.payload.surface, expected_content)
        if expected != verdict.payload.content_binding:
            raise ScanVerdictError(
                "content_binding mismatch: this verdict is not about the content "
                "supplied (different bytes, or a different surface)"
            )

    return verdict.payload


__all__ = [
    "SCAN_VERDICT_VERSION",
    "DetectorKind",
    "ScanDirection",
    "ScanDisposition",
    "ScanSurface",
    "ScanVerdict",
    "ScanVerdictError",
    "ScanVerdictPayload",
    "ScanVerdictSignature",
    "canonicalize_scan_verdict_v1",
    "compute_content_binding",
    "sign_scan_verdict",
    "verify_scan_verdict",
]
