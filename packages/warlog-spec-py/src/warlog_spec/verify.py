"""Standalone audit-chain verifier.

The verifier accepts newline-delimited JSON exported either as the
``JsonlFilePersister`` format or as public ``SignedAuditRow`` objects.
It verifies HMAC-SHA256 chains without importing the Warlog runtime.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from warlog_spec.audit_chain import (
    CANONICALIZATION_FORMAT_V1,
    AuditChainBroken,
    canonicalize_v1,
    compute_genesis,
    compute_signature,
)
from warlog_spec.provider_abi import AuditRow, SignedAuditRow


@dataclass(frozen=True)
class VerificationReport:
    """Successful verification summary."""

    rows: int
    tenant_id: str | None
    head_signature: str | None


class AuditChainVerificationError(AuditChainBroken):
    """Raised when standalone audit-chain verification fails."""

    def __init__(self, message: str, *, row_number: int | None = None) -> None:
        super().__init__(message)
        self.row_number = row_number


@dataclass(frozen=True)
class _SignedEntry:
    row: AuditRow
    prev_hash: str
    signature: str
    canonical_bytes: bytes


def _require_str(entry: dict[str, Any], key: str, row_number: int) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise AuditChainVerificationError(
            f"row {row_number} missing required string field {key!r}",
            row_number=row_number,
        )
    return value


def _decode_base64(value: str, row_number: int) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AuditChainVerificationError(
            f"row {row_number} canonicalBytes is not valid base64",
            row_number=row_number,
        ) from exc


def _decode_entry(entry: dict[str, Any], row_number: int) -> _SignedEntry:
    if "row" in entry:
        try:
            row = AuditRow.model_validate(entry["row"])
        except ValidationError as exc:
            raise AuditChainVerificationError(
                f"row {row_number} payload does not match AuditRow",
                row_number=row_number,
            ) from exc

        canonicalization_format = entry.get(
            "canonicalizationFormat", CANONICALIZATION_FORMAT_V1
        )
        if canonicalization_format != CANONICALIZATION_FORMAT_V1:
            raise AuditChainVerificationError(
                f"row {row_number} unsupported canonicalization format {canonicalization_format!r}",
                row_number=row_number,
            )

        canonical_value = entry.get("canonicalBytes")
        canonical_bytes = (
            _decode_base64(canonical_value, row_number)
            if isinstance(canonical_value, str)
            else canonicalize_v1(row)
        )
        return _SignedEntry(
            row=row,
            prev_hash=_require_str(entry, "prevHash", row_number),
            signature=_require_str(entry, "signature", row_number),
            canonical_bytes=canonical_bytes,
        )

    try:
        signed = SignedAuditRow.model_validate(entry)
    except ValidationError as exc:
        raise AuditChainVerificationError(
            f"row {row_number} is neither JsonlFilePersister nor SignedAuditRow format",
            row_number=row_number,
        ) from exc

    if signed.attestation.algorithm != "HMAC-SHA256":
        raise AuditChainVerificationError(
            f"row {row_number} unsupported signature algorithm {signed.attestation.algorithm!r}",
            row_number=row_number,
        )
    if signed.attestation.canonicalization_format != CANONICALIZATION_FORMAT_V1:
        raise AuditChainVerificationError(
            f"row {row_number} unsupported canonicalization format "
            f"{signed.attestation.canonicalization_format!r}",
            row_number=row_number,
        )

    return _SignedEntry(
        row=signed.payload,
        prev_hash=signed.attestation.prev_row_hash,
        signature=signed.attestation.signature_value,
        canonical_bytes=canonicalize_v1(signed.payload),
    )


def verify_audit_jsonl_file(path: str | Path, secret: bytes) -> VerificationReport:
    """Verify a JSONL audit chain and return a summary.

    ``secret`` is treated as raw bytes. If it comes from a text file,
    trailing newlines are significant and should be removed by the
    operator before verification.
    """

    if not secret:
        raise AuditChainVerificationError("secret is empty")

    rows = 0
    tenant_id: str | None = None
    expected_prev: str | None = None
    head_signature: str | None = None

    with Path(path).open(encoding="utf-8") as file_handle:
        for line_number, line in enumerate(file_handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            row_number = rows + 1
            try:
                raw_entry = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise AuditChainVerificationError(
                    f"row {row_number} is not valid JSON (line {line_number})",
                    row_number=row_number,
                ) from exc
            if not isinstance(raw_entry, dict):
                raise AuditChainVerificationError(
                    f"row {row_number} must be a JSON object",
                    row_number=row_number,
                )

            signed = _decode_entry(raw_entry, row_number)
            if tenant_id is None:
                tenant_id = signed.row.tenant_id
                expected_prev = compute_genesis(tenant_id, secret)
            elif signed.row.tenant_id != tenant_id:
                raise AuditChainVerificationError(
                    f"row {row_number} tenantId changed from {tenant_id!r} "
                    f"to {signed.row.tenant_id!r}",
                    row_number=row_number,
                )

            if signed.prev_hash != expected_prev:
                raise AuditChainVerificationError(
                    f"row {row_number} prevHash mismatch",
                    row_number=row_number,
                )

            recomputed = compute_signature(signed.prev_hash, signed.canonical_bytes, secret)
            if recomputed != signed.signature:
                raise AuditChainVerificationError(
                    f"row {row_number} signature mismatch",
                    row_number=row_number,
                )

            rows += 1
            head_signature = signed.signature
            expected_prev = signed.signature

    return VerificationReport(rows=rows, tenant_id=tenant_id, head_signature=head_signature)


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="warlog-verify",
        description="Verify a Warlog audit-chain JSONL file.",
    )
    parser.add_argument("audit_log", type=Path, help="JSONL audit chain to verify")
    parser.add_argument(
        "--secret-file",
        type=Path,
        required=True,
        help="File containing the raw HMAC secret bytes",
    )
    args = parser.parse_args(argv)

    try:
        secret = args.secret_file.read_bytes()
        report = verify_audit_jsonl_file(args.audit_log, secret)
    except (OSError, AuditChainVerificationError) as exc:
        print(f"FAIL : {exc}", file=sys.stderr)
        return 1

    print(f"OK : {report.rows} rows, chain valid, no gaps, no tampering")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())


__all__ = [
    "AuditChainVerificationError",
    "VerificationReport",
    "verify_audit_jsonl_file",
]