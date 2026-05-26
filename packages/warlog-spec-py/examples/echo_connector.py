"""Reference example — a minimal AbiConnector in ~50 lines.

Run this file's ``__main__`` block to see the connector instantiate,
declare its capability, and "execute" against an in-memory state.
A real connector replaces the ``apply``/``verify`` bodies with HTTP
calls to the upstream vendor (Elastic, Splunk, CrowdStrike, …).

The point of the example : a third-party integrator can write this
file in 50 lines and have a conformant connector. No Warlog backend
import required. Just ``pip install warlog-spec``.
"""

from __future__ import annotations

import asyncio
from typing import ClassVar
from uuid import uuid4

from warlog_spec import (
    AbiConnector,
    ApprovalDescriptor,
    ApprovalLevel,
    AuthDescriptor,
    ConnectorAbiError,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorKind,
    EgressDescriptor,
    ExecutionOutcome,
    FailureCategory,
    ResponseActionId,
    ResponseActionResult,
    ResponseActionScope,
    ResponseActionSpec,
    ResponseSubject,
)


class EchoConnector(AbiConnector):
    """In-memory test connector — acknowledges alerts by echoing them.

    Implements one action (``alert.acknowledge``) against a local set,
    not a real vendor. Demonstrates the four lifecycle hooks plus
    vendor-side idempotency via ``spec.idempotency_key``.
    """

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="echo",
        connector_version="0.1.0",
        vendor="Echo Test",
        kind=ConnectorKind.OTHER,
        auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY, scopes=["echo.respond"]),
        egress=EgressDescriptor(
            supports_response_actions=[ResponseActionId.ALERT_ACKNOWLEDGE]
        ),
        compat=ConnectorCompat(warlog_spec_min="1.0", warlog_spec_max="1.0"),
    )

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self._acknowledged: set[str] = set()
        # Vendor-side idempotency: real connectors forward
        # spec.idempotency_key to the upstream API; this in-memory
        # version dedupes the same way a real vendor would.
        self._applied_keys: dict[str, str] = {}

    async def authenticate(self) -> None:
        if not self.config.get("api_key"):
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "echo: api_key required in config",
                vendor_code="401",
            )

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        if spec.action_id is not ResponseActionId.ALERT_ACKNOWLEDGE:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"echo does not implement {spec.action_id.value!r}",
            )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        cached_task = self._applied_keys.get(spec.idempotency_key)
        if cached_task is not None:
            return _success(spec, vendor_task_id=cached_task, dedup=True)

        alert_id = spec.subject.selector_value
        self._acknowledged.add(alert_id)
        task_id = str(uuid4())
        self._applied_keys[spec.idempotency_key] = task_id
        return _success(spec, vendor_task_id=task_id, dedup=False)

    async def verify(
        self, spec: ResponseActionSpec, result: ResponseActionResult
    ) -> bool:
        return spec.subject.selector_value in self._acknowledged


def _success(
    spec: ResponseActionSpec, *, vendor_task_id: str, dedup: bool
) -> ResponseActionResult:
    return ResponseActionResult(
        execution_id="",  # the runtime stamps it
        action_id=spec.action_id,
        outcome=ExecutionOutcome.SUCCESS,
        subject=spec.subject,
        details={"vendor_task_id": vendor_task_id, "vendor_dedup": dedup},
    )


# ---------------------------------------------------------------------------
# Smoke run — exercise the lifecycle without a runtime
# ---------------------------------------------------------------------------


async def _main() -> None:
    connector = EchoConnector({"api_key": "test-key"})
    spec = ResponseActionSpec(
        action_id=ResponseActionId.ALERT_ACKNOWLEDGE,
        subject=ResponseSubject(
            kind=ResponseActionScope.PLATFORM,
            selector_type="alert_id",
            selector_value="alert-001",
        ),
        approval=ApprovalDescriptor(
            required=False, level=ApprovalLevel.NONE, rationale="example smoke"
        ),
        idempotency_key="example-key-001",
    )

    await connector.authenticate()
    await connector.dry_run(spec)
    result = await connector.apply(spec)
    verified = await connector.verify(spec, result)

    print(f"outcome   = {result.outcome.value}")
    print(f"verified  = {verified}")
    print(f"vendor    = {result.details}")


if __name__ == "__main__":
    asyncio.run(_main())
