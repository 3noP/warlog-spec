from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from warlog_spec import AiAgentRef, ComplianceScope, ResponseActionId
from warlog_spec.audit_chain import canonicalize_v1, compute_genesis, compute_signature
from warlog_spec.conformance import produce_audit_row
from warlog_spec.integrate import JsonlFilePersister, WarlogClient, agent_run, audited
from warlog_spec.provider_abi import AuditRow
from warlog_spec.verify import AuditChainVerificationError, _cli, verify_audit_jsonl_file

SECRET = b"verify-secret-do-not-ship"


def _write_jsonl_chain(path: Path) -> None:
    client = WarlogClient(
        tenant_id="tenant-verify",
        hmac_secret=SECRET,
        pii_salt=b"verify-pii-salt",
        persister=JsonlFilePersister(path),
        selector_key_id="tenant:verify:salt:v1",
    )

    @audited(
        client=client,
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject_arg="user_email",
    )
    def revoke_tokens(user_email: str) -> None:
        return None

    agent = AiAgentRef(
        model="gpt-4o",
        model_version="2026-04-01",
        system_prompt_hash="a" * 64,
        agent_run_id="verify-run-001",
    )
    with agent_run(
        client,
        agent=agent,
        actor_id="playbook.verify",
        alert_id="alert-verify-001",
        alert_payload=b'{"alert":"verify"}',
        compliance_scope=[ComplianceScope.GDPR],
    ):
        revoke_tokens("alice@example.test")


def test_verify_jsonl_file_accepts_valid_persister_chain(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    _write_jsonl_chain(audit_log)

    report = verify_audit_jsonl_file(audit_log, SECRET)

    assert report.rows == 2
    assert report.tenant_id == "tenant-verify"
    assert report.head_signature is not None


def test_verify_jsonl_file_rejects_tampered_signature(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    _write_jsonl_chain(audit_log)
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    second_entry = json.loads(lines[1])
    second_entry["signature"] = "0" * 64
    lines[1] = json.dumps(second_entry, sort_keys=True)
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainVerificationError, match="row 2 signature mismatch"):
        verify_audit_jsonl_file(audit_log, SECRET)


def test_verify_jsonl_file_accepts_public_signed_audit_row(tmp_path: Path) -> None:
    row = AuditRow.model_validate(produce_audit_row())
    prev_hash = compute_genesis(row.tenant_id, SECRET)
    canonical_bytes = canonicalize_v1(row)
    signature = compute_signature(prev_hash, canonical_bytes, SECRET)
    signed_row = {
        "payload": row.model_dump(mode="json", by_alias=True),
        "attestation": {
            "prevRowHash": prev_hash,
            "signatureValue": signature,
            "algorithm": "HMAC-SHA256",
            "canonicalizationFormat": "v1",
            "keyId": "tenant:verify:hmac:v1",
        },
    }
    audit_log = tmp_path / "signed-audit-row.jsonl"
    audit_log.write_text(json.dumps(signed_row) + "\n", encoding="utf-8")

    report = verify_audit_jsonl_file(audit_log, SECRET)

    assert report.rows == 1
    assert report.tenant_id == row.tenant_id


def test_verify_jsonl_file_rejects_tampered_canonical_bytes(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    _write_jsonl_chain(audit_log)
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    first_entry = json.loads(lines[0])
    canonical_bytes = base64.b64decode(first_entry["canonicalBytes"])
    first_entry["canonicalBytes"] = base64.b64encode(canonical_bytes + b" ").decode("ascii")
    lines[0] = json.dumps(first_entry, sort_keys=True)
    audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainVerificationError, match="row 1 signature mismatch"):
        verify_audit_jsonl_file(audit_log, SECRET)


def test_warlog_verify_cli_reports_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    audit_log = tmp_path / "audit.jsonl"
    secret_file = tmp_path / "secret.bin"
    _write_jsonl_chain(audit_log)
    secret_file.write_bytes(SECRET)

    code = _cli([str(audit_log), "--secret-file", str(secret_file)])

    captured = capsys.readouterr()
    assert code == 0
    assert "OK : 2 rows, chain valid, no gaps, no tampering" in captured.out