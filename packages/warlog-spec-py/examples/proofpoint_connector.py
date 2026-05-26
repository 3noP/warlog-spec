"""Proofpoint TAP + TRAP connector — reference implementation.

Wraps the public Proofpoint Targeted Attack Protection (TAP) and
Threat Response Auto-Pull (TRAP) APIs to implement the canonical SOC
email-response sub-graph.

Actions covered :

- :data:`ResponseActionId.EMAIL_QUARANTINE`     → TRAP create-incident + quarantine
- :data:`ResponseActionId.EMAIL_RECALL`         → TRAP create-incident + recall
- :data:`ResponseActionId.EMAIL_RELEASE`        → TRAP release-from-quarantine
- :data:`ResponseActionId.EMAIL_BLOCK_SENDER`   → POST /v2/orgs/{orgId}/blocked_senders
- :data:`ResponseActionId.EMAIL_UNBLOCK_SENDER` → DELETE blocked_senders entry

The Proofpoint audit (see ``docs/canon-migration/12-email-gap-audit.md``)
surfaced 3 gaps in the email family — sender-side block/unblock and
quarantine release — all cross-validated against M365 Defender for
Email, Mimecast, Cisco Email Security, and Google Workspace before
admission.

**Auth model :** Proofpoint uses HTTP Basic auth with a Service
Principal (TAP API) and a separate API key for TRAP. Both flows are
documented at https://help.proofpoint.com/Threat_Response/. The
reference accepts both credential sets in config; production
deployments rotate them via Vault.

Configuration shape::

    {
        "tap_base_url":   "https://tap-api-v2.proofpoint.com",
        "tap_principal":  "<service-principal>",
        "tap_secret":     "redacted",
        "trap_base_url":  "https://trap.example.test",
        "trap_api_key":   "redacted",
        "org_id":         "<orgId for blocked_senders>",
    }

What this file proves :

- An email-security vendor with TWO product surfaces (TAP for
  threat data + TRAP for response orchestration) fits the same ABI.
  The connector multiplexes between them based on action_id.
- "Quarantine" is not the same as "block sender" — these are
  semantically distinct actions that an analyst reaches for in
  different scenarios. Promoting both to canon keeps the audit
  chain expressive.

**Runtime-test status :** spec-conformant, written against
Proofpoint's documented APIs. Not yet exercised against a live
tenant. PRs welcome.

Requires ``httpx``.
"""

from __future__ import annotations

import asyncio
from base64 import b64encode
from typing import Any, ClassVar
from uuid import uuid4

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


class ProofpointConnector(AbiConnector):
    """ABI connector for Proofpoint TAP + TRAP."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="proofpoint-tap-trap",
        connector_version="0.1.0",
        vendor="Proofpoint",
        kind=ConnectorKind.EMAIL,
        auth=AuthDescriptor(
            model=ConnectorAuthModel.API_KEY,
            scopes=[
                "tap.threat.read",
                "trap.incident.write",
                "trap.response.write",
            ],
        ),
        egress=EgressDescriptor(
            supports_response_actions=[
                ResponseActionId.EMAIL_QUARANTINE,
                ResponseActionId.EMAIL_RECALL,
                ResponseActionId.EMAIL_RELEASE,
                ResponseActionId.EMAIL_BLOCK_SENDER,
                ResponseActionId.EMAIL_UNBLOCK_SENDER,
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
        tap_base = config.get("tap_base_url")
        trap_base = config.get("trap_base_url")
        principal = config.get("tap_principal")
        secret = config.get("tap_secret")
        trap_key = config.get("trap_api_key")
        org_id = config.get("org_id")
        if not isinstance(tap_base, str) or not tap_base:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "proofpoint: config['tap_base_url'] is required",
            )
        if not isinstance(trap_base, str) or not trap_base:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "proofpoint: config['trap_base_url'] is required",
            )
        if not all(
            isinstance(v, str) and v for v in (principal, secret, trap_key, org_id)
        ):
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "proofpoint: tap_principal, tap_secret, trap_api_key, org_id all required",
            )
        self._org_id = org_id
        self._tap = httpx.AsyncClient(
            base_url=tap_base.rstrip("/"),
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "Accept": "application/json",
                "Authorization": "Basic "
                + b64encode(f"{principal}:{secret}".encode()).decode(),
            },
        )
        self._trap = httpx.AsyncClient(
            base_url=trap_base.rstrip("/"),
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {trap_key}",
            },
        )
        self._applied: dict[str, str] = {}

    # -- Lifecycle hooks --------------------------------------------------

    async def authenticate(self) -> None:
        # Both TAP and TRAP use static credentials; smoke each with a
        # cheap GET. TAP : /v2/people/vap (very-attacked-people, low
        # cost). TRAP : /api/incidents?limit=1.
        try:
            tap_resp = await self._tap.get("/v2/people/vap", params={"window": 1})
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"proofpoint: TAP auth network error: {exc}",
            ) from exc
        if tap_resp.status_code not in (200, 204):
            raise _map_pp_error(tap_resp, op="auth:tap")
        try:
            trap_resp = await self._trap.get("/api/incidents", params={"limit": 1})
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"proofpoint: TRAP auth network error: {exc}",
            ) from exc
        if trap_resp.status_code not in (200, 204):
            raise _map_pp_error(trap_resp, op="auth:trap")

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        if spec.action_id not in _SUPPORTED:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"proofpoint does not implement {spec.action_id.value!r}",
            )
        if not spec.subject.selector_value:
            raise ConnectorAbiError(
                FailureCategory.NOT_FOUND,
                "proofpoint: subject.selector_value is required",
            )
        # Quarantine / recall / release operate on a message id (RFC
        # 5322 Message-ID or vendor message id). Block/unblock operate
        # on a sender email address or domain.
        if spec.action_id in {
            ResponseActionId.EMAIL_QUARANTINE,
            ResponseActionId.EMAIL_RECALL,
            ResponseActionId.EMAIL_RELEASE,
        } and spec.subject.selector_type not in {"message_id", "envelope_id"}:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"proofpoint {spec.action_id.value} requires "
                "subject.selector_type in {'message_id','envelope_id'}",
            )
        if spec.action_id in {
            ResponseActionId.EMAIL_BLOCK_SENDER,
            ResponseActionId.EMAIL_UNBLOCK_SENDER,
        } and spec.subject.selector_type not in {"email", "domain"}:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"proofpoint {spec.action_id.value} requires "
                "subject.selector_type in {'email','domain'}",
            )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        cached = self._applied.get(spec.idempotency_key)
        if cached is not None:
            return _success(spec, vendor_resource_id=cached, dedup=True)

        if spec.action_id is ResponseActionId.EMAIL_QUARANTINE:
            resource_id = await self._trap_action(spec, action="quarantine")
        elif spec.action_id is ResponseActionId.EMAIL_RECALL:
            resource_id = await self._trap_action(spec, action="recall")
        elif spec.action_id is ResponseActionId.EMAIL_RELEASE:
            resource_id = await self._trap_action(spec, action="release")
        elif spec.action_id is ResponseActionId.EMAIL_BLOCK_SENDER:
            resource_id = await self._block_sender(spec, add=True)
        elif spec.action_id is ResponseActionId.EMAIL_UNBLOCK_SENDER:
            resource_id = await self._block_sender(spec, add=False)
        else:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"proofpoint: unroutable action {spec.action_id.value!r}",
            )

        self._applied[spec.idempotency_key] = resource_id
        return _success(spec, vendor_resource_id=resource_id, dedup=False)

    async def verify(
        self, spec: ResponseActionSpec, result: ResponseActionResult
    ) -> bool:
        if spec.action_id in {
            ResponseActionId.EMAIL_QUARANTINE,
            ResponseActionId.EMAIL_RECALL,
            ResponseActionId.EMAIL_RELEASE,
        }:
            # TRAP returns the incident id ; verify by fetching its
            # state and confirming the response succeeded.
            incident_id = result.details.get("vendor_resource_id")
            if not isinstance(incident_id, str):
                return False
            try:
                resp = await self._trap.get(f"/api/incidents/{incident_id}")
            except httpx.HTTPError as exc:
                raise ConnectorAbiError(
                    FailureCategory.TRANSIENT,
                    f"proofpoint: incident GET error: {exc}",
                ) from exc
            if resp.status_code != 200:
                return False
            state = (resp.json().get("state") or "").lower()
            return state in {"closed", "resolved", "completed"}

        if spec.action_id is ResponseActionId.EMAIL_BLOCK_SENDER:
            return await self._sender_in_blocklist(spec.subject.selector_value)
        if spec.action_id is ResponseActionId.EMAIL_UNBLOCK_SENDER:
            return not await self._sender_in_blocklist(spec.subject.selector_value)
        return False

    # -- Vendor-specific operations --------------------------------------

    async def _trap_action(
        self, spec: ResponseActionSpec, *, action: str
    ) -> str:
        """Create a TRAP incident and trigger the response.

        TRAP's documented flow : POST /api/incidents to create an
        incident with the message id and the requested response
        (quarantine | recall | release). TRAP returns an incident id
        used for status polling.
        """
        body = {
            "summary": f"warlog-abi {spec.action_id.value} on {spec.subject.selector_value}",
            "evidence": {
                spec.subject.selector_type: spec.subject.selector_value,
            },
            "responses": [{"type": action}],
            "external_id": spec.idempotency_key,
        }
        try:
            resp = await self._trap.post("/api/incidents", json=body)
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"proofpoint: TRAP create network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 201, 202):
            raise _map_pp_error(resp, op=f"trap:{action}")
        body_resp = resp.json()
        incident_id = body_resp.get("id")
        if not isinstance(incident_id, (str, int)):
            raise ConnectorAbiError(
                FailureCategory.STATE_CONFLICT,
                "proofpoint: TRAP did not return an incident id",
                vendor_message=str(body_resp)[:200],
            )
        return str(incident_id)

    async def _block_sender(self, spec: ResponseActionSpec, *, add: bool) -> str:
        sender = spec.subject.selector_value
        if add:
            try:
                resp = await self._tap.post(
                    f"/v2/orgs/{self._org_id}/blocked_senders",
                    json={"sender": sender, "type": spec.subject.selector_type},
                )
            except httpx.HTTPError as exc:
                raise ConnectorAbiError(
                    FailureCategory.TRANSIENT,
                    f"proofpoint: block sender network error: {exc}",
                ) from exc
            if resp.status_code not in (200, 201):
                raise _map_pp_error(resp, op="block_sender")
            return f"blocked:{sender}"

        # unblock — Proofpoint deletes by entry id; we resolve sender → id first.
        try:
            search = await self._tap.get(
                f"/v2/orgs/{self._org_id}/blocked_senders",
                params={"q": sender},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"proofpoint: blocked-senders search network error: {exc}",
            ) from exc
        if search.status_code == 404:
            return f"absent:{sender}"
        if search.status_code != 200:
            raise _map_pp_error(search, op="unblock:search")
        entries = search.json().get("entries") or []
        match = next(
            (e for e in entries if isinstance(e, dict) and e.get("sender") == sender),
            None,
        )
        if not match:
            return f"absent:{sender}"
        entry_id = match.get("id")
        try:
            del_resp = await self._tap.delete(
                f"/v2/orgs/{self._org_id}/blocked_senders/{entry_id}"
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"proofpoint: unblock DELETE network error: {exc}",
            ) from exc
        if del_resp.status_code not in (200, 204):
            raise _map_pp_error(del_resp, op="unblock:delete")
        return f"unblocked:{sender}"

    async def _sender_in_blocklist(self, sender: str) -> bool:
        try:
            resp = await self._tap.get(
                f"/v2/orgs/{self._org_id}/blocked_senders",
                params={"q": sender},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"proofpoint: blocked-senders verify error: {exc}",
            ) from exc
        if resp.status_code == 404:
            return False
        if resp.status_code != 200:
            raise _map_pp_error(resp, op="verify:blocked_senders")
        entries = resp.json().get("entries") or []
        return any(
            isinstance(e, dict) and e.get("sender") == sender for e in entries
        )

    async def aclose(self) -> None:
        await self._tap.aclose()
        await self._trap.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SUPPORTED: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.EMAIL_QUARANTINE,
        ResponseActionId.EMAIL_RECALL,
        ResponseActionId.EMAIL_RELEASE,
        ResponseActionId.EMAIL_BLOCK_SENDER,
        ResponseActionId.EMAIL_UNBLOCK_SENDER,
    }
)


_PP_HTTP_TO_CATEGORY: dict[int, tuple[FailureCategory, bool]] = {
    400: (FailureCategory.POLICY, False),
    401: (FailureCategory.AUTH, False),
    403: (FailureCategory.POLICY, False),
    404: (FailureCategory.NOT_FOUND, False),
    409: (FailureCategory.STATE_CONFLICT, False),
    429: (FailureCategory.TRANSIENT, True),
}


def _map_pp_error(resp: httpx.Response, *, op: str) -> ConnectorAbiError:
    status = resp.status_code
    if status in _PP_HTTP_TO_CATEGORY:
        category, retryable = _PP_HTTP_TO_CATEGORY[status]
    elif 500 <= status < 600:
        category, retryable = FailureCategory.TRANSIENT, True
    else:
        category, retryable = FailureCategory.POLICY, False
    try:
        body: dict[str, Any] = resp.json()
    except ValueError:
        body = {}
    return ConnectorAbiError(
        category,
        f"proofpoint {op} failed: HTTP {status}",
        retryable=retryable,
        vendor_code=str(body.get("error_code") or status),
        vendor_message=str(body.get("error") or body.get("message") or "")[:200] or None,
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
    cap = ProofpointConnector.capability
    print(f"connector_id     = {cap.connector_id}")
    print(f"vendor           = {cap.vendor}")
    print(f"kind             = {cap.kind.value}")
    print(f"auth_model       = {cap.auth.model.value}")
    print(f"actions          = {[a.value for a in cap.egress.supports_response_actions]}")
    print(f"dry_run.scope    = {cap.dry_run.scope.value}")


if __name__ == "__main__":
    asyncio.run(_main())
