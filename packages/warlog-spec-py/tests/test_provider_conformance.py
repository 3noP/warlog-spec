from __future__ import annotations

import asyncio
import json
import sys

from warlog_spec.conformance import _cli
from warlog_spec.provider_abi import (
    ConnectorCapability,
    ConnectorError,
    ResponseActionResult,
    ResponseActionSpec,
)
from warlog_spec.provider_conformance import run_mock_provider_level_4


def test_mock_provider_level_4_report_is_semantically_complete() -> None:
    report = asyncio.run(run_mock_provider_level_4())

    assert report["specVersion"] == "1.0"
    assert report["level"] == 4
    assert report["scenario"]["id"] == "mock-vendor.host-isolate.v1"

    capability = ConnectorCapability.model_validate(report["capability"])
    spec = ResponseActionSpec.model_validate(report["spec"])
    result = ResponseActionResult.model_validate(report["apply"]["result"])
    replay = ResponseActionResult.model_validate(report["idempotency"]["result"])
    unsupported = ConnectorError.model_validate(report["unsupportedAction"]["error"])

    assert spec.action_id in capability.egress.supports_response_actions
    assert report["dryRun"]["mutationsBefore"] == 0
    assert report["dryRun"]["mutationsAfter"] == 0
    assert result.outcome == "success"
    assert report["verify"]["verified"] is True
    assert replay.outcome == "success"
    assert report["idempotency"]["mutationsAfterReplay"] == report["apply"]["mutationsAfter"]
    assert report["idempotency"]["sameVendorTask"] is True
    assert unsupported.category == "policy"


def test_provider_check_cli_writes_level_4_report(tmp_path, monkeypatch) -> None:
    out = tmp_path / "provider-report.json"
    monkeypatch.setattr(sys, "argv", ["warlog-spec", "provider-check", "--out", str(out)])

    assert _cli() == 0

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["level"] == 4
    assert report["verify"]["verified"] is True