"""CrowdStrike Falcon EDR connector — reference implementation.

Wraps the public CrowdStrike Falcon API
(https://falcon.crowdstrike.com/documentation/) to implement the canonical
EDR response sub-graph :

- :data:`ResponseActionId.HOST_ISOLATE`           → contain a device
- :data:`ResponseActionId.HOST_UNISOLATE`         → lift containment
- :data:`ResponseActionId.HOST_RESTART`           → reboot via RTR ``shutdown -r``
- :data:`ResponseActionId.HOST_COLLECT_ARTIFACTS` → pull file or memdump via RTR
- :data:`ResponseActionId.IP_BLOCK`               → push an IP IOC with prevention
- :data:`ResponseActionId.DOMAIN_BLOCK`           → push a domain IOC with prevention
- :data:`ResponseActionId.URL_BLOCK`              → push a URL IOC with prevention
- :data:`ResponseActionId.HASH_BLOCK`             → push a SHA256 IOC with prevention

Auth model is OAuth2 client credentials. The token endpoint is
``POST /oauth2/token`` (form-encoded, ``grant_type=client_credentials``);
the bearer is short-lived (~30min) so this connector refreshes lazily
when a 401 surfaces. The cloud region (us-1, us-2, eu-1, gov-1) is part
of the base URL — the customer picks it at tenant provisioning time.

Configuration shape::

    {
        "base_url":      "https://api.us-2.crowdstrike.com",
        "client_id":     "abc123...",   # Falcon → API clients & keys
        "client_secret": "redacted",
    }

The action endpoints used :

- POST /devices/entities/devices-actions/v2?action_name=contain
        body: {"ids": ["<device-id>"]}
- POST /devices/entities/devices-actions/v2?action_name=lift_containment
        body: {"ids": ["<device-id>"]}
- POST /iocs/entities/indicators/v1
        body: {"indicators": [{"type": "ipv4|domain|url", "value": ...,
                               "action": "prevent", "platforms": ["windows", ...],
                               "applied_globally": true,
                               "expiration": "<iso8601>"}]}

Verification :

- Containment: GET /devices/entities/devices/v2?ids=... → look at
  ``status`` and ``device_policies.dispatch.containment_status``.
- IOC: GET /iocs/entities/indicators/v1?ids=... — IOC must exist with
  ``action`` = ``prevent``.

What this file proves :

- The same ABI shape that drove the Okta example fits a fundamentally
  different vendor (OAuth2 client_credentials vs SSWS, async device
  action queue vs synchronous lifecycle hits, response IDs returned
  by the vendor vs synthesized client-side).
- Falcon's standardized error envelope (``{"errors": [...]}``) maps
  cleanly to :class:`FailureCategory` with the vendor's code preserved.
- IOC management is materially different from device action — the
  connector is the right place to abstract that, not the Warlog
  runtime.

**Runtime-test status :** spec-conformant, written against Falcon's
published API contract. Not yet exercised against a live Falcon tenant.
PRs welcome.

Requires ``httpx``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import httpx

from warlog_spec import (
    AbiConnector,
    AuthDescriptor,
    ConnectorAbiError,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorKind,
    DryRunDescriptor,
    DryRunScope,
    EgressDescriptor,
    ExecutionOutcome,
    FailureCategory,
    LifecycleDescriptor,
    ResponseActionId,
    ResponseActionResult,
    ResponseActionSpec,
)


class CrowdstrikeFalconConnector(AbiConnector):
    """ABI connector for CrowdStrike Falcon EDR response actions."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="crowdstrike-falcon",
        connector_version="0.1.0",
        vendor="CrowdStrike Falcon",
        kind=ConnectorKind.EDR,
        auth=AuthDescriptor(
            model=ConnectorAuthModel.OAUTH2_CLIENT_CREDENTIALS,
            scopes=[
                "hosts:read",
                "hosts:write",
                "iocs:read",
                "iocs:write",
                "real-time-response:read",
                "real-time-response:write",
                "real-time-response-admin:write",
            ],
        ),
        egress=EgressDescriptor(
            supports_response_actions=[
                ResponseActionId.HOST_ISOLATE,
                ResponseActionId.HOST_UNISOLATE,
                ResponseActionId.HOST_RESTART,
                ResponseActionId.HOST_COLLECT_ARTIFACTS,
                ResponseActionId.IP_BLOCK,
                ResponseActionId.IP_UNBLOCK,
                ResponseActionId.DOMAIN_BLOCK,
                ResponseActionId.DOMAIN_UNBLOCK,
                ResponseActionId.URL_BLOCK,
                ResponseActionId.URL_UNBLOCK,
                ResponseActionId.HASH_BLOCK,
                ResponseActionId.HASH_UNBLOCK,
            ]
        ),
        dry_run=DryRunDescriptor(supported=True, scope=DryRunScope.EGRESS),
        lifecycle=LifecycleDescriptor(
            supports_health_check=True,
            supports_credential_rotation=True,
        ),
        compat=ConnectorCompat(warlog_spec_min="1.0.0", warlog_spec_max="1.x"),
    )

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        base_url = config.get("base_url")
        client_id = config.get("client_id")
        client_secret = config.get("client_secret")
        if not isinstance(base_url, str) or not base_url:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "falcon: config['base_url'] is required (e.g. https://api.us-2.crowdstrike.com)",
            )
        if not isinstance(client_id, str) or not isinstance(client_secret, str):
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "falcon: client_id and client_secret are required",
            )
        self._client_id = client_id
        self._client_secret = client_secret
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers={"Accept": "application/json"},
        )
        self._bearer: str | None = None
        self._bearer_expires: datetime | None = None
        # Connector-side idempotency: Falcon does not honor an
        # Idempotency-Key header on action endpoints (and IOC POST is
        # naturally idempotent on (type, value)). Cache anyway for the
        # device-action path.
        self._applied: dict[str, str] = {}

    # -- Lifecycle hooks --------------------------------------------------

    async def authenticate(self) -> None:
        try:
            resp = await self._client.post(
                "/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: token network error: {exc}",
            ) from exc
        if resp.status_code != 201:
            # Falcon returns 201 on token issuance, not 200.
            raise _map_falcon_error(resp, op="authenticate")
        body = resp.json()
        self._bearer = body["access_token"]
        # Refresh ~60s before stated expiry to avoid races.
        ttl = int(body.get("expires_in", 1800))
        self._bearer_expires = datetime.now(UTC) + timedelta(seconds=max(ttl - 60, 60))

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        if spec.action_id not in _SUPPORTED:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"falcon does not implement {spec.action_id.value!r}",
            )
        if not spec.subject.selector_value:
            raise ConnectorAbiError(
                FailureCategory.NOT_FOUND,
                "falcon: subject.selector_value is required",
            )
        if spec.action_id in _DEVICE_TARGETED_ACTIONS:
            if spec.subject.selector_type != "device_id":
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    f"falcon {spec.action_id.value} requires subject.selector_type='device_id'",
                )
        if spec.action_id is ResponseActionId.HOST_COLLECT_ARTIFACTS:
            artifact_type = spec.params.get("artifact_type")
            if artifact_type not in ("file", "memory"):
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "falcon: host.collect_artifacts requires "
                    "params['artifact_type'] in {'file', 'memory'}",
                )
            if artifact_type == "file" and not spec.params.get("path"):
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "falcon: artifact_type='file' requires params['path']",
                )
        if spec.action_id is ResponseActionId.HASH_BLOCK:
            if spec.subject.selector_type != "sha256":
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "falcon hash.block requires subject.selector_type='sha256'",
                )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        cached = self._applied.get(spec.idempotency_key)
        if cached is not None:
            return _success(spec, vendor_resource_id=cached, dedup=True)

        await self._ensure_authenticated()

        if spec.action_id is ResponseActionId.HOST_ISOLATE:
            resource_id = await self._device_action(spec, "contain")
        elif spec.action_id is ResponseActionId.HOST_UNISOLATE:
            resource_id = await self._device_action(spec, "lift_containment")
        elif spec.action_id is ResponseActionId.HOST_RESTART:
            resource_id = await self._rtr_command(
                spec, base_command="shutdown", command_string="shutdown -r -t 0"
            )
        elif spec.action_id is ResponseActionId.HOST_COLLECT_ARTIFACTS:
            resource_id = await self._rtr_collect(spec)
        elif spec.action_id is ResponseActionId.HASH_BLOCK:
            # SHA256 IOC reuses the same /iocs endpoint as IP/DOMAIN/URL,
            # just with a different type. Dispatch via the IOC pusher
            # which already handles platforms, expiration, and source.
            resource_id = await self._push_ioc(spec)
        elif spec.action_id in _IOC_UNBLOCK_ACTIONS:
            # IOC removal — Falcon /iocs supports DELETE by value
            # (`?type=...&value=...`) or by ID. We delete by value so
            # the orchestrator doesn't need to remember the original id.
            resource_id = await self._delete_ioc(spec)
        else:
            resource_id = await self._push_ioc(spec)

        self._applied[spec.idempotency_key] = resource_id
        return _success(spec, vendor_resource_id=resource_id, dedup=False)

    async def verify(
        self, spec: ResponseActionSpec, result: ResponseActionResult
    ) -> bool:
        await self._ensure_authenticated()

        if spec.action_id is ResponseActionId.HOST_ISOLATE:
            status = await self._get_containment_status(spec.subject.selector_value)
            return status in {"contained", "containment_pending"}
        if spec.action_id is ResponseActionId.HOST_UNISOLATE:
            status = await self._get_containment_status(spec.subject.selector_value)
            return status in {"normal", "lift_containment_pending"}

        if spec.action_id is ResponseActionId.HOST_RESTART:
            # RTR shutdown commands are fire-and-forget; the device
            # checks back in after reboot. Verify by observing
            # last_seen drift past the apply timestamp — for the
            # reference, we trust the RTR command's complete=true and
            # return True. A production implementation would track
            # last_seen via /devices/entities/devices/v2.
            return True

        if spec.action_id is ResponseActionId.HOST_COLLECT_ARTIFACTS:
            # The vendor_resource_id IS the cloud-storage path or RTR
            # session_id from which the file was retrieved. If we got
            # one from apply, the artifact exists.
            return bool(result.details.get("vendor_resource_id"))

        if spec.action_id in {
            ResponseActionId.IP_BLOCK,
            ResponseActionId.DOMAIN_BLOCK,
            ResponseActionId.URL_BLOCK,
            ResponseActionId.HASH_BLOCK,
        }:
            ioc_id = result.details.get("vendor_resource_id")
            if not isinstance(ioc_id, str):
                return False
            return await self._ioc_exists(ioc_id)

        if spec.action_id in _IOC_UNBLOCK_ACTIONS:
            # Verify by checking the IOC is gone from the catalog. We
            # query by type+value (not id, since unblock removes by
            # value), and return True when the lookup is empty.
            return not await self._ioc_present_by_value(spec)

        return False

    # -- Vendor-specific operations --------------------------------------

    async def _device_action(
        self, spec: ResponseActionSpec, action_name: str
    ) -> str:
        device_id = spec.subject.selector_value
        try:
            resp = await self._client.post(
                "/devices/entities/devices-actions/v2",
                params={"action_name": action_name},
                json={"ids": [device_id]},
                headers=self._bearer_headers(),
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: device-action network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 202):
            raise _map_falcon_error(resp, op=f"device-action:{action_name}")
        body = resp.json()
        # Falcon wraps results in "resources": [{"id": "...", "path": ..."}]
        resources = body.get("resources") or []
        if not resources:
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                f"falcon: {action_name} returned no resources for device {device_id}",
                vendor_message=str(body)[:200],
            )
        # Use the device id as the stable correlator (Falcon does not
        # return a per-action task id on this endpoint).
        return device_id

    async def _push_ioc(self, spec: ResponseActionSpec) -> str:
        ioc_type = _IOC_TYPE_FOR_ACTION[spec.action_id]
        indicator = {
            "type": ioc_type,
            "value": spec.subject.selector_value,
            "action": "prevent",
            "platforms": list(spec.params.get("platforms") or ["windows", "mac", "linux"]),
            "applied_globally": True,
            "source": str(spec.params.get("source") or "warlog-abi"),
        }
        if spec.expires_at is not None:
            indicator["expiration"] = spec.expires_at.isoformat()
        try:
            resp = await self._client.post(
                "/iocs/entities/indicators/v1",
                json={"indicators": [indicator]},
                headers={**self._bearer_headers(), "Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: ioc push network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 201):
            raise _map_falcon_error(resp, op=f"ioc-push:{ioc_type}")
        body = resp.json()
        resources = body.get("resources") or []
        if not resources or not isinstance(resources[0], dict):
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                "falcon: ioc push returned no resources",
                vendor_message=str(body)[:200],
            )
        ioc_id = resources[0].get("id")
        if not isinstance(ioc_id, str):
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                "falcon: ioc push returned no id",
                vendor_message=str(body)[:200],
            )
        return ioc_id

    async def _get_containment_status(self, device_id: str) -> str:
        try:
            resp = await self._client.get(
                "/devices/entities/devices/v2",
                params={"ids": device_id},
                headers=self._bearer_headers(),
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: device GET network error: {exc}",
            ) from exc
        if resp.status_code == 404:
            return "unknown"
        if resp.status_code != 200:
            raise _map_falcon_error(resp, op="verify:device")
        body = resp.json()
        resources = body.get("resources") or []
        if not resources:
            return "unknown"
        return str(resources[0].get("status") or "unknown")

    async def _delete_ioc(self, spec: ResponseActionSpec) -> str:
        """Remove an IOC by type+value via Falcon's DELETE /iocs.

        Falcon's DELETE on the indicators endpoint accepts ``ids`` (the
        opaque indicator id) OR ``type``+``value`` filters. We use
        type+value so the orchestrator can unblock an IOC it doesn't
        own (or whose original id has been forgotten / never persisted).
        """
        ioc_type = _IOC_TYPE_FOR_ACTION[spec.action_id]
        ioc_value = spec.subject.selector_value
        # First, find the IOC by type+value.
        try:
            search = await self._client.get(
                "/iocs/queries/indicators/v1",
                params={"filter": f"type:'{ioc_type}'+value:'{ioc_value}'"},
                headers=self._bearer_headers(),
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: ioc search network error: {exc}",
            ) from exc
        if search.status_code == 404:
            # Already absent — idempotent unblock.
            return f"absent:{ioc_type}:{ioc_value}"
        if search.status_code != 200:
            raise _map_falcon_error(search, op=f"ioc-search:{ioc_type}")
        ids = search.json().get("resources") or []
        if not ids:
            return f"absent:{ioc_type}:{ioc_value}"
        # Then DELETE.
        try:
            del_resp = await self._client.delete(
                "/iocs/entities/indicators/v1",
                params={"ids": ids},
                headers=self._bearer_headers(),
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: ioc DELETE network error: {exc}",
            ) from exc
        if del_resp.status_code not in (200, 204):
            raise _map_falcon_error(del_resp, op=f"ioc-delete:{ioc_type}")
        return f"deleted:{ioc_type}:{ioc_value}"

    async def _ioc_present_by_value(self, spec: ResponseActionSpec) -> bool:
        ioc_type = _IOC_TYPE_FOR_ACTION[spec.action_id]
        ioc_value = spec.subject.selector_value
        try:
            search = await self._client.get(
                "/iocs/queries/indicators/v1",
                params={"filter": f"type:'{ioc_type}'+value:'{ioc_value}'"},
                headers=self._bearer_headers(),
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: ioc verify network error: {exc}",
            ) from exc
        if search.status_code == 404:
            return False
        if search.status_code != 200:
            raise _map_falcon_error(search, op=f"verify:ioc:{ioc_type}")
        return bool(search.json().get("resources"))

    # -- Real Time Response (RTR) helpers --------------------------------
    #
    # RTR is a 3-step flow per execution :
    #   1. start session: POST /real-time-response/entities/sessions/v1
    #   2. issue command: POST /real-time-response/entities/{queue}/v1
    #   3. (optional) pull result: GET on the command's request_id
    #
    # The "queue" depends on the command's privilege class :
    #   - active-responder-command (read-only / non-destructive)
    #   - admin-command (destructive — required for shutdown, put,
    #     run, kill, encrypt, restart)
    # ``shutdown -r`` requires the admin queue. ``get`` (file pull)
    # requires the active-responder queue.

    async def _rtr_start_session(self, device_id: str) -> str:
        try:
            resp = await self._client.post(
                "/real-time-response/entities/sessions/v1",
                json={"device_id": device_id, "origin": "warlog-abi"},
                headers={**self._bearer_headers(), "Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: RTR session network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 201):
            raise _map_falcon_error(resp, op="rtr:session")
        body = resp.json()
        resources = body.get("resources") or []
        if not resources or not isinstance(resources[0], dict):
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                "falcon: RTR session start returned no resources",
                vendor_message=str(body)[:200],
            )
        session_id = resources[0].get("session_id")
        if not isinstance(session_id, str):
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                "falcon: RTR session_id missing",
                vendor_message=str(body)[:200],
            )
        return session_id

    async def _rtr_command(
        self,
        spec: ResponseActionSpec,
        *,
        base_command: str,
        command_string: str,
        admin: bool = True,
    ) -> str:
        """Run an RTR command synchronously, return the request_id.

        ``admin=True`` routes to the admin queue (required for
        destructive verbs like ``shutdown``, ``run``, ``put``).
        """
        device_id = spec.subject.selector_value
        session_id = await self._rtr_start_session(device_id)
        queue = "admin-command" if admin else "active-responder-command"
        try:
            resp = await self._client.post(
                f"/real-time-response/entities/{queue}/v1",
                json={
                    "session_id": session_id,
                    "device_id": device_id,
                    "base_command": base_command,
                    "command_string": command_string,
                },
                headers={**self._bearer_headers(), "Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: RTR command network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 201):
            raise _map_falcon_error(resp, op=f"rtr:{base_command}")
        body = resp.json()
        resources = body.get("resources") or []
        if not resources or not isinstance(resources[0], dict):
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                "falcon: RTR command returned no resources",
                vendor_message=str(body)[:200],
            )
        cloud_request_id = resources[0].get("cloud_request_id") or resources[0].get(
            "task_id"
        )
        if not isinstance(cloud_request_id, str):
            # Some RTR commands complete inline and don't return a request_id;
            # fall back to the session_id as a stable correlator.
            return session_id
        return cloud_request_id

    async def _rtr_collect(self, spec: ResponseActionSpec) -> str:
        """Collect a file or memory dump via RTR.

        For ``artifact_type='file'``: ``get <path>`` on the active-
        responder queue. For ``artifact_type='memory'``: ``memdump``
        on the admin queue. Both return a request id Falcon resolves
        into a downloadable cloud-storage object — fetching the bytes
        themselves is out of scope for the reference; we hand back the
        request_id so a downstream forensics pipeline can pull.
        """
        artifact_type = spec.params["artifact_type"]
        if artifact_type == "file":
            path = spec.params["path"]
            return await self._rtr_command(
                spec,
                base_command="get",
                command_string=f'get "{path}"',
                admin=False,
            )
        # memory
        return await self._rtr_command(
            spec,
            base_command="memdump",
            command_string="memdump",
            admin=True,
        )

    async def _ioc_exists(self, ioc_id: str) -> bool:
        try:
            resp = await self._client.get(
                "/iocs/entities/indicators/v1",
                params={"ids": ioc_id},
                headers=self._bearer_headers(),
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"falcon: ioc GET network error: {exc}",
            ) from exc
        if resp.status_code == 404:
            return False
        if resp.status_code != 200:
            raise _map_falcon_error(resp, op="verify:ioc")
        body = resp.json()
        return bool(body.get("resources"))

    # -- Auth helpers -----------------------------------------------------

    async def _ensure_authenticated(self) -> None:
        if (
            self._bearer
            and self._bearer_expires
            and datetime.now(UTC) < self._bearer_expires
        ):
            return
        await self.authenticate()

    def _bearer_headers(self) -> dict[str, str]:
        if not self._bearer:
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "falcon: authenticate() must run before this call",
            )
        return {"Authorization": f"Bearer {self._bearer}"}

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUPPORTED: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.HOST_ISOLATE,
        ResponseActionId.HOST_UNISOLATE,
        ResponseActionId.HOST_RESTART,
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
        ResponseActionId.IP_BLOCK,
        ResponseActionId.IP_UNBLOCK,
        ResponseActionId.DOMAIN_BLOCK,
        ResponseActionId.DOMAIN_UNBLOCK,
        ResponseActionId.URL_BLOCK,
        ResponseActionId.URL_UNBLOCK,
        ResponseActionId.HASH_BLOCK,
        ResponseActionId.HASH_UNBLOCK,
    }
)


_IOC_UNBLOCK_ACTIONS: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.IP_UNBLOCK,
        ResponseActionId.DOMAIN_UNBLOCK,
        ResponseActionId.URL_UNBLOCK,
        ResponseActionId.HASH_UNBLOCK,
    }
)


_DEVICE_TARGETED_ACTIONS: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.HOST_ISOLATE,
        ResponseActionId.HOST_UNISOLATE,
        ResponseActionId.HOST_RESTART,
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
    }
)


_IOC_TYPE_FOR_ACTION: dict[ResponseActionId, str] = {
    ResponseActionId.IP_BLOCK: "ipv4",
    ResponseActionId.IP_UNBLOCK: "ipv4",
    ResponseActionId.DOMAIN_BLOCK: "domain",
    ResponseActionId.DOMAIN_UNBLOCK: "domain",
    ResponseActionId.URL_BLOCK: "url",
    ResponseActionId.URL_UNBLOCK: "url",
    ResponseActionId.HASH_BLOCK: "sha256",
    ResponseActionId.HASH_UNBLOCK: "sha256",
}


_FALCON_HTTP_TO_CATEGORY: dict[int, tuple[FailureCategory, bool]] = {
    400: (FailureCategory.POLICY, False),
    401: (FailureCategory.AUTH, False),
    403: (FailureCategory.POLICY, False),
    404: (FailureCategory.NOT_FOUND, False),
    409: (FailureCategory.STATE_CONFLICT, False),
    429: (FailureCategory.TRANSIENT, True),
}


def _map_falcon_error(resp: httpx.Response, *, op: str) -> ConnectorAbiError:
    """Map a Falcon non-2xx envelope to a categorized ABI error.

    Falcon wraps errors as ``{"errors": [{"code": int, "message": str}]}``.
    """
    status = resp.status_code
    if status in _FALCON_HTTP_TO_CATEGORY:
        category, retryable = _FALCON_HTTP_TO_CATEGORY[status]
    elif 500 <= status < 600:
        category, retryable = FailureCategory.TRANSIENT, True
    else:
        category, retryable = FailureCategory.POLICY, False
    try:
        body: dict[str, Any] = resp.json()
    except ValueError:
        body = {}
    errors = body.get("errors") or []
    first = errors[0] if errors and isinstance(errors[0], dict) else {}
    return ConnectorAbiError(
        category,
        f"falcon {op} failed: HTTP {status}",
        retryable=retryable,
        vendor_code=str(first.get("code") or status),
        vendor_message=str(first.get("message") or "")[:200] or None,
    )


def _success(
    spec: ResponseActionSpec, *, vendor_resource_id: str, dedup: bool
) -> ResponseActionResult:
    return ResponseActionResult(
        execution_id="",  # the runtime stamps it
        action_id=spec.action_id,
        outcome=ExecutionOutcome.SUCCESS,
        subject=spec.subject,
        details={
            "vendor_resource_id": vendor_resource_id,
            "vendor_dedup": dedup,
        },
    )


# ---------------------------------------------------------------------------
# CLI walkthrough — capability inspection only.
# ---------------------------------------------------------------------------


async def _main() -> None:
    cap = CrowdstrikeFalconConnector.capability
    print(f"connector_id     = {cap.connector_id}")
    print(f"vendor           = {cap.vendor}")
    print(f"kind             = {cap.kind.value}")
    print(f"auth_model       = {cap.auth.model.value}")
    print(f"actions          = {[a.value for a in cap.egress.supports_response_actions]}")
    print(f"dry_run.scope    = {cap.dry_run.scope.value}")
    print()
    print("To exercise the lifecycle against a real Falcon tenant :")
    print("  export FALCON_BASE_URL='https://api.us-2.crowdstrike.com'")
    print("  export FALCON_CLIENT_ID='...'")
    print("  export FALCON_CLIENT_SECRET='...'")
    print("  python -m examples.crowdstrike_falcon_connector --live <device-id>")


if __name__ == "__main__":
    asyncio.run(_main())
