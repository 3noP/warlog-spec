"""Provider ABI Level 4 mock-vendor conformance helpers.

Level 4 proves a provider can execute the public ABI lifecycle against
a vendor-like surface without depending on the Warlog product runtime.
This module ships a deterministic in-memory mock vendor plus a reference
connector that exercises:

- capability declaration,
- authenticate -> dry_run -> apply -> verify ordering,
- side-effect-free dry-run,
- connector-side idempotency,
- policy rejection for unsupported actions.

The output is a JSON-serializable evidence report consumed by the public
``warlog-spec/tests/conformance/runner.py --level 4`` command.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, ClassVar

from warlog_spec.abi import AbiConnector, ConnectorAbiError
from warlog_spec.provider_abi import (
    ABI_VERSION,
    ApprovalDescriptor,
    ApprovalLevel,
    AuthDescriptor,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorError,
    ConnectorKind,
    DryRunDescriptor,
    DryRunScope,
    EgressDescriptor,
    ExecutionOutcome,
    FailureCategory,
    ResponseActionId,
    ResponseActionResult,
    ResponseActionScope,
    ResponseActionSpec,
    ResponseSubject,
)

MOCK_VENDOR_ID = "warlog.mock-response-vendor.v1"
MOCK_PROVIDER_SCENARIO_ID = "mock-vendor.host-isolate.v1"
MOCK_HOST_ID = "host-001"
MOCK_IDEMPOTENCY_KEY = "mock-provider-host-isolate-001"


def _dump(model: Any) -> dict[str, Any]:
    return model.model_dump(mode="json", by_alias=True)


class MockResponseVendor:
    """Deterministic vendor-like surface for Level 4 provider tests.

    It is deliberately smaller than a real EDR API. The harness only
    needs one observable mutation, one read path, and an idempotency
    ledger to prove the Provider ABI semantics.
    """

    def __init__(self, *, api_key: str = "test-key") -> None:
        self.api_key = api_key
        self.hosts: dict[str, dict[str, bool]] = {MOCK_HOST_ID: {"isolated": False}}
        self.idempotency: dict[str, str] = {}
        self.mutation_count = 0

    def authenticate(self, api_key: object) -> None:
        if api_key != self.api_key:
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "mock vendor rejected api key",
                vendor_code="mock.auth.invalid",
            )

    def get_host(self, host_id: str) -> dict[str, bool]:
        host = self.hosts.get(host_id)
        if host is None:
            raise ConnectorAbiError(
                FailureCategory.NOT_FOUND,
                f"mock host {host_id!r} not found",
                vendor_code="mock.host.not_found",
            )
        return host

    def isolate_host(self, host_id: str, idempotency_key: str) -> dict[str, object]:
        cached_task_id = self.idempotency.get(idempotency_key)
        if cached_task_id is not None:
            return {"task_id": cached_task_id, "dedup": True}

        host = self.get_host(host_id)
        if host["isolated"]:
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                f"mock host {host_id!r} already isolated",
                vendor_code="mock.host.already_isolated",
            )

        task_id = "mock-task-" + hashlib.sha256(
            idempotency_key.encode("utf-8")
        ).hexdigest()[:16]
        host["isolated"] = True
        self.idempotency[idempotency_key] = task_id
        self.mutation_count += 1
        return {"task_id": task_id, "dedup": False}

    def host_isolated(self, host_id: str) -> bool:
        return self.get_host(host_id)["isolated"]


class MockVendorConnector(AbiConnector):
    """Reference Level 4 connector against :class:`MockResponseVendor`."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="mock-response-vendor",
        connector_version="0.1.0",
        vendor="Warlog Mock Response Vendor",
        kind=ConnectorKind.EDR,
        auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY, scopes=["mock.respond"]),
        egress=EgressDescriptor(
            supports_response_actions=[ResponseActionId.HOST_ISOLATE]
        ),
        dry_run=DryRunDescriptor(supported=True, scope=DryRunScope.EGRESS),
        compat=ConnectorCompat(warlog_spec_min="1.0", warlog_spec_max="1.0"),
    )

    @property
    def vendor(self) -> MockResponseVendor:
        vendor = self.config.get("vendor")
        if isinstance(vendor, MockResponseVendor):
            return vendor
        raise ConnectorAbiError(
            FailureCategory.POLICY,
            "mock vendor instance missing from connector config",
            vendor_code="mock.vendor.missing",
        )

    async def authenticate(self) -> None:
        self.vendor.authenticate(self.config.get("api_key"))

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        self._ensure_supported(spec)
        host = self.vendor.get_host(spec.subject.selector_value)
        if host["isolated"]:
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                "mock host is already isolated",
                vendor_code="mock.host.already_isolated",
            )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        self._ensure_supported(spec)
        mutation = self.vendor.isolate_host(
            spec.subject.selector_value,
            spec.idempotency_key,
        )
        return ResponseActionResult(
            execution_id="",
            action_id=spec.action_id,
            outcome=ExecutionOutcome.SUCCESS,
            subject=spec.subject,
            details={
                "vendorTaskId": mutation["task_id"],
                "vendorDedup": mutation["dedup"],
                "mutationCount": self.vendor.mutation_count,
            },
        )

    async def verify(
        self,
        spec: ResponseActionSpec,
        result: ResponseActionResult,
    ) -> bool:
        self._ensure_supported(spec)
        return result.outcome is ExecutionOutcome.SUCCESS and self.vendor.host_isolated(
            spec.subject.selector_value
        )

    def _ensure_supported(self, spec: ResponseActionSpec) -> None:
        if spec.action_id is not ResponseActionId.HOST_ISOLATE:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"mock connector does not implement {spec.action_id.value!r}",
                vendor_code="mock.action.unsupported",
            )


def mock_provider_action_spec() -> ResponseActionSpec:
    """Canonical request used by the Level 4 mock-provider scenario."""

    return ResponseActionSpec(
        action_id=ResponseActionId.HOST_ISOLATE,
        subject=ResponseSubject(
            kind=ResponseActionScope.ENDPOINT,
            selector_type="agent_id",
            selector_value=MOCK_HOST_ID,
        ),
        approval=ApprovalDescriptor(
            required=False,
            level=ApprovalLevel.NONE,
            rationale="Level 4 mock-provider conformance scenario",
        ),
        idempotency_key=MOCK_IDEMPOTENCY_KEY,
    )


def mock_unsupported_action_spec() -> ResponseActionSpec:
    return ResponseActionSpec(
        action_id=ResponseActionId.PROCESS_KILL,
        subject=ResponseSubject(
            kind=ResponseActionScope.ENDPOINT,
            selector_type="pid",
            selector_value="4242",
        ),
        approval=ApprovalDescriptor(
            required=False,
            level=ApprovalLevel.NONE,
            rationale="Unsupported-action negative control",
        ),
        idempotency_key="mock-provider-unsupported-001",
    )


async def run_mock_provider_level_4(
    connector_cls: type[AbiConnector] = MockVendorConnector,
    *,
    implementation_name: str = "warlog-spec-py",
    implementation_version: str = "0.1.0",
    implementation_language: str = "python",
    config: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Run the Level 4 mock-vendor provider contract and return evidence.

    The default connector is the package reference implementation. Advanced
    adopters can pass a custom connector class as long as it targets the
    same :class:`MockResponseVendor` supplied in the config.
    """

    vendor = MockResponseVendor()
    connector_config: dict[str, object] = {"api_key": "test-key", "vendor": vendor}
    if config:
        connector_config.update(config)

    connector = connector_cls(connector_config)
    capability = ConnectorCapability.model_validate(connector_cls.capability)
    spec = mock_provider_action_spec()

    await connector.authenticate()

    mutations_before_dry_run = vendor.mutation_count
    await connector.dry_run(spec)
    mutations_after_dry_run = vendor.mutation_count

    result = await connector.apply(spec)
    verified = await connector.verify(spec, result)
    mutations_after_apply = vendor.mutation_count

    replay_result = await connector.apply(spec)
    mutations_after_replay = vendor.mutation_count

    unsupported_error: ConnectorError | None = None
    try:
        await connector.dry_run(mock_unsupported_action_spec())
    except ConnectorAbiError as exc:
        unsupported_error = exc.to_connector_error()

    return {
        "specVersion": ABI_VERSION,
        "level": 4,
        "implementation": {
            "name": implementation_name,
            "version": implementation_version,
            "language": implementation_language,
        },
        "scenario": {
            "id": MOCK_PROVIDER_SCENARIO_ID,
            "mockVendor": MOCK_VENDOR_ID,
            "actionId": spec.action_id.value,
        },
        "capability": _dump(capability),
        "spec": _dump(spec),
        "dryRun": {
            "called": True,
            "mutationsBefore": mutations_before_dry_run,
            "mutationsAfter": mutations_after_dry_run,
        },
        "apply": {
            "called": True,
            "result": _dump(result),
            "mutationsAfter": mutations_after_apply,
        },
        "verify": {"called": True, "verified": verified},
        "idempotency": {
            "replayed": True,
            "result": _dump(replay_result),
            "mutationsAfterReplay": mutations_after_replay,
            "sameVendorTask": result.details.get("vendorTaskId")
            == replay_result.details.get("vendorTaskId"),
        },
        "unsupportedAction": {
            "rejected": unsupported_error is not None,
            "error": _dump(unsupported_error) if unsupported_error else None,
        },
    }


__all__ = [
    "MOCK_PROVIDER_SCENARIO_ID",
    "MOCK_VENDOR_ID",
    "MockResponseVendor",
    "MockVendorConnector",
    "mock_provider_action_spec",
    "mock_unsupported_action_spec",
    "run_mock_provider_level_4",
]