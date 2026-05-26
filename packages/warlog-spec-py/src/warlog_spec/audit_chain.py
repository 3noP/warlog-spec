"""HMAC audit-chain crypto primitives — verification side.

A third party who operates against a Warlog runtime can verify the
connector audit chain end-to-end without trusting the runtime. This
module exposes only the pure crypto primitives needed for
verification :

- :func:`canonicalize_v1` — produce the canonical bytes for an
  ``AuditRow`` under format version ``v1``
- :func:`compute_genesis` — first-row predecessor hash for a tenant
- :func:`compute_signature` — HMAC over ``prev_hash || canonical_bytes``
- :class:`AuditChainBroken` — exception type raised on integrity failure

The runtime side (write path, append-only store, claim-and-publish
relay) lives in the Warlog backend and is NOT part of this package.
A verifier walks rows it exported from the runtime DB, ordered by
``chain_seq``, and recomputes each HMAC against the persisted
``canonical_bytes``.

.. important:: **The crypto path uses ``canonical_bytes`` STORED at
   write time, not a re-serialization of the current Pydantic model.**
   Pydantic schema evolution (adding optional fields, etc.) cannot
   invalidate verification of historical rows because the bytes are
   exactly what was signed. A future ``canonicalize_v2`` would land
   alongside ``v1`` and the verifier dispatches on the per-row
   ``canonicalization_format``.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from warlog_spec.provider_abi import AuditRow

# Stable salt mixed into the genesis hash. Per-tenant rotation lives
# in tenant settings on the runtime side; this constant is the
# default fallback that runtimes and verifiers MUST agree on.
_GENESIS_SALT = b"warlog-spec/v1.0/audit-chain/genesis"

CANONICALIZATION_FORMAT_V1 = "v1"


class AuditChainBroken(Exception):
    """Raised when chain integrity verification fails."""


def canonicalize_v1(row: AuditRow) -> bytes:
    """v1 canonicalization: sorted-keys JSON of ``model_dump(mode="json")``.

    .. warning:: **WRITER STABILITY TRIPWIRE.** The output of this
       function is what gets HMAC-signed *at write time*. The signed
       bytes are persisted alongside the signature, so changing this
       function does NOT silently invalidate historical rows
       (verification reads back the persisted bytes, not a re-dump).

       However, changing this function still matters : future rows
       written by the modified writer will have different bytes than
       past ones. To introduce a new canonicalization (e.g. CBOR,
       COSE) :

       1. Add a ``canonicalize_v2`` function alongside this one.
       2. Bump the writer's emitted ``canonicalization_format`` to ``"v2"``.
       3. Old ``v1`` rows continue to verify against this function.

    **Security : structurally immune to delimiter-injection attacks.**
    The HMAC signing function combines ``prev_hash || "|" || canonical_bytes``.
    A naive flat-concatenation format would let an attacker stuff the
    ``"|"`` separator inside a string field and produce a byte
    sequence that collides with a different legitimate row. v1 is
    immune by construction :

    - ``prev_hash`` is always 64 hex chars (output of HMAC-SHA256),
      restricted to ``[0-9a-f]``. ``"|"`` cannot appear in it.
    - ``canonical_bytes`` always begins with ``{`` (JSON object) and
      contains string values inside ``""`` quote-delimiters. Any
      ``"|"`` inside a string value is enclosed by JSON-escaped
      quotes, not promoted to the row level.

    The boundary between the two byte ranges is fixed-position
    (64 hex chars + literal pipe + JSON object), not search-based.
    Two semantically different rows produce structurally different
    canonical bytes — no input on a string field can collapse them.
    See ``test_canonicalization_immune_to_delimiter_injection`` for
    the pin test.
    """
    return json.dumps(
        row.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_genesis(tenant_id: str, secret: bytes) -> str:
    """First-row predecessor hash for a tenant's chain."""
    h = hmac.new(secret, _GENESIS_SALT + tenant_id.encode("utf-8"), hashlib.sha256)
    return h.hexdigest()


def compute_signature(
    prev_hash: str,
    canonical_bytes: bytes,
    secret: bytes,
) -> str:
    """HMAC-SHA256 over ``prev_hash || "|" || canonical_bytes``.

    Operates on raw bytes — no Pydantic re-serialization. Callers
    feed in the bytes that were stored at write time (or computed via
    :func:`canonicalize_v1` for newly produced rows).
    """
    h = hmac.new(secret, prev_hash.encode("ascii"), hashlib.sha256)
    h.update(b"|")
    h.update(canonical_bytes)
    return h.hexdigest()


__all__ = [
    "CANONICALIZATION_FORMAT_V1",
    "AuditChainBroken",
    "canonicalize_v1",
    "compute_genesis",
    "compute_signature",
]
