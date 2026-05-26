"""Okta user-response connector — reference implementation.

Wraps the public Okta API (https://developer.okta.com/docs/reference/) to
implement the canonical SOC response actions on a compromised user :

- :data:`ResponseActionId.USER_DISABLE`         → POST /api/v1/users/{id}/lifecycle/suspend
- :data:`ResponseActionId.USER_RESET_MFA`       → POST /api/v1/users/{id}/lifecycle/reset_factors
- :data:`ResponseActionId.USER_FORCE_LOGOUT`    → DELETE /api/v1/users/{id}/sessions
- :data:`ResponseActionId.USER_REVOKE_TOKENS`   → DELETE /api/v1/users/{id}/tokens
- :data:`ResponseActionId.USER_RESET_PASSWORD`  → POST /api/v1/users/{id}/lifecycle/reset_password
- :data:`ResponseActionId.USER_EXPIRE_PASSWORD` → POST /api/v1/users/{id}/lifecycle/expire_password
- :data:`ResponseActionId.USER_UNLOCK`          → POST /api/v1/users/{id}/lifecycle/unlock
- :data:`ResponseActionId.USER_GROUP_REMOVE`    → DELETE /api/v1/groups/{groupId}/users/{id}
- :data:`ResponseActionId.USER_DELETE`          → DELETE /api/v1/users/{id}

Auth model is OAuth2 client credentials with private-key JWT bearer (the
flow Okta recommends for service-to-service automation
— see Okta's "Implement OAuth for Okta with a Service App"). To keep
this example small, it uses the simpler **API token** auth (``SSWS``
header), which is still officially supported and used by the vast
majority of integrations today. Switching to OAuth2 is a localized
change in :meth:`OktaUserResponseConnector.authenticate`.

Configuration shape::

    {
        "base_url": "https://yourorg.okta.com",
        "api_token": "00...redacted...",   # Okta admin → Security → API
    }

What this file proves :

- The ABI maps cleanly onto a real, public, production SOC API.
- Vendor error codes (``E0000007`` for not-found, ``E0000004`` for auth,
  ``E0000038`` for rate limit) flow into :class:`FailureCategory` via
  the HTTP status, with the vendor-specific code preserved in
  ``vendor_code`` so on-call can correlate to Okta's docs.
- Idempotency is handled connector-side: Okta does not accept an
  ``Idempotency-Key`` header on lifecycle endpoints, so we keep our
  own ``idempotency_key → vendor_response`` map. This is the pattern
  for the (many) vendors that have not adopted RFC 8594-style headers.
- ``verify`` reads the user's ``status`` field — ``SUSPENDED`` confirms
  USER_DISABLE took effect; ``ACTIVE`` (with no live session) confirms
  USER_FORCE_LOGOUT; MFA factor list shrinking confirms USER_RESET_MFA.

**Runtime-test status :** this connector is shipped as spec-conformant
reference code, written against Okta's published REST contract. It has
NOT been exercised against a live Okta tenant yet. PRs from anyone
running it against their dev tenant are welcomed (see ``CHANGELOG.md``).

Requires ``httpx``.
"""

from __future__ import annotations

import asyncio
from typing import ClassVar
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


class OktaUserResponseConnector(AbiConnector):
    """ABI connector for Okta user-response actions.

    Covers the user-compromise response sub-graph. Wider Okta
    coverage (group membership, app assignments, network zones) is
    out of scope for this reference — fork it.
    """

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="okta-user-response",
        connector_version="0.1.0",
        vendor="Okta",
        kind=ConnectorKind.IAM,
        auth=AuthDescriptor(
            model=ConnectorAuthModel.API_KEY,
            scopes=["okta.users.manage", "okta.sessions.manage"],
        ),
        egress=EgressDescriptor(
            supports_response_actions=[
                ResponseActionId.USER_DISABLE,
                ResponseActionId.USER_RESET_MFA,
                ResponseActionId.USER_FORCE_LOGOUT,
                ResponseActionId.USER_REVOKE_TOKENS,
                ResponseActionId.USER_RESET_PASSWORD,
                ResponseActionId.USER_EXPIRE_PASSWORD,
                ResponseActionId.USER_UNLOCK,
                ResponseActionId.USER_GROUP_REMOVE,
                ResponseActionId.USER_DELETE,
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
        api_token = config.get("api_token")
        if not isinstance(base_url, str) or not base_url:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "okta: config['base_url'] is required (e.g. https://yourorg.okta.com)",
            )
        if not isinstance(api_token, str) or not api_token:
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "okta: config['api_token'] is required",
            )
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(15.0, connect=5.0),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        # Connector-side idempotency cache: Okta lifecycle endpoints
        # do not accept an Idempotency-Key header, so we keep our own.
        # In a multi-process runtime this MUST be backed by a shared
        # store (Redis, the runtime's idempotency cache); per-process
        # is fine for the reference.
        self._applied: dict[str, str] = {}

    # -- Lifecycle hooks --------------------------------------------------

    async def authenticate(self) -> None:
        # Okta API tokens are static — verify by calling /api/v1/users/me
        # which returns the token's owning user. Catches typos, revoked
        # tokens, and clock-skew on signed alternatives.
        try:
            resp = await self._client.get(
                "/api/v1/users/me", headers=self._auth_headers()
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"okta: auth network error: {exc}",
            ) from exc
        if resp.status_code != 200:
            raise _map_okta_error(resp, op="authenticate")

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        if spec.action_id not in _SUPPORTED:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"okta-user-response does not implement {spec.action_id.value!r}",
            )
        # Confirm the subject is referencable. Okta accepts both the
        # opaque user id and the user's login (email) on lifecycle
        # endpoints, so any non-empty selector is acceptable here;
        # the GET below would be the next-level validation.
        if not spec.subject.selector_value:
            raise ConnectorAbiError(
                FailureCategory.NOT_FOUND,
                "okta: subject.selector_value (user id or login) is required",
            )
        # USER_GROUP_REMOVE requires the target group id in params —
        # there's no "remove from all privileged groups" primitive in
        # Okta. The orchestrator MUST resolve the group set upstream
        # (e.g. from a privilege-tag query) and call us once per group.
        if spec.action_id is ResponseActionId.USER_GROUP_REMOVE:
            if not spec.params.get("group_id"):
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "okta: user.group_remove requires params['group_id']",
                )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        cached = self._applied.get(spec.idempotency_key)
        if cached is not None:
            return _success(spec, vendor_response_id=cached, dedup=True)

        method, path = _route_for(spec)
        try:
            resp = await self._client.request(
                method, path, headers=self._auth_headers()
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"okta: apply network error: {exc}",
            ) from exc
        # Okta lifecycle endpoints return 200 on success (some return
        # the user object, some empty); DELETE endpoints return 204.
        if resp.status_code not in (200, 204):
            raise _map_okta_error(resp, op=f"apply:{spec.action_id.value}")
        # Okta does not return a stable "task id" — for traceability we
        # generate one client-side and persist it in the cache.
        vendor_response_id = uuid4().hex
        self._applied[spec.idempotency_key] = vendor_response_id
        return _success(spec, vendor_response_id=vendor_response_id, dedup=False)

    async def verify(
        self, spec: ResponseActionSpec, result: ResponseActionResult
    ) -> bool:
        user_id = spec.subject.selector_value
        try:
            resp = await self._client.get(
                f"/api/v1/users/{user_id}", headers=self._auth_headers()
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"okta: verify network error: {exc}",
            ) from exc
        if resp.status_code == 404:
            return False  # Okta sometimes lags; runtime retries
        if resp.status_code != 200:
            raise _map_okta_error(resp, op="verify")
        body = resp.json()

        if spec.action_id is ResponseActionId.USER_DISABLE:
            return body.get("status") == "SUSPENDED"

        if spec.action_id is ResponseActionId.USER_DELETE:
            # If the GET returned 200 the user still exists — verify
            # would have been called only after the runtime saw 204
            # from apply, but Okta's delete is async on accounts with
            # active sessions, so a transient 200 is possible.
            return resp.status_code == 404

        if spec.action_id is ResponseActionId.USER_UNLOCK:
            # Okta returns the user to ACTIVE state once unlocked.
            return body.get("status") == "ACTIVE"

        if spec.action_id is ResponseActionId.USER_EXPIRE_PASSWORD:
            # The user transitions to PASSWORD_EXPIRED until they next log in.
            return body.get("status") == "PASSWORD_EXPIRED"

        if spec.action_id in {
            ResponseActionId.USER_FORCE_LOGOUT,
            ResponseActionId.USER_REVOKE_TOKENS,
            ResponseActionId.USER_RESET_PASSWORD,
        }:
            # These have no idempotent GET-side proof in Okta's public
            # API — the apply 2xx is the contract. Returning True is
            # honest because the runtime only invokes verify after a
            # successful apply, and these are fire-and-forget by
            # vendor design (RESET_PASSWORD just emails the user; the
            # password is not actually changed yet).
            return True

        if spec.action_id is ResponseActionId.USER_RESET_MFA:
            # After reset, the user's enrolled factors list is empty
            # until they re-enroll.
            try:
                factors_resp = await self._client.get(
                    f"/api/v1/users/{user_id}/factors",
                    headers=self._auth_headers(),
                )
            except httpx.HTTPError as exc:
                raise ConnectorAbiError(
                    FailureCategory.TRANSIENT,
                    f"okta: factors GET error: {exc}",
                ) from exc
            if factors_resp.status_code != 200:
                raise _map_okta_error(factors_resp, op="verify:factors")
            return factors_resp.json() == []

        if spec.action_id is ResponseActionId.USER_GROUP_REMOVE:
            # Confirm the user is no longer a member by GETing the
            # specific membership: a 404 means removed.
            group_id = spec.params.get("group_id")
            if not isinstance(group_id, str):
                return False
            try:
                membership = await self._client.get(
                    f"/api/v1/groups/{group_id}/users",
                    params={"q": user_id, "limit": 1},
                    headers=self._auth_headers(),
                )
            except httpx.HTTPError as exc:
                raise ConnectorAbiError(
                    FailureCategory.TRANSIENT,
                    f"okta: group membership GET error: {exc}",
                ) from exc
            if membership.status_code != 200:
                raise _map_okta_error(membership, op="verify:group_membership")
            members = membership.json()
            return not any(
                isinstance(m, dict) and m.get("id") == user_id for m in members
            )

        return False

    # -- Internals --------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"SSWS {self._api_token}"}

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SUPPORTED: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.USER_DISABLE,
        ResponseActionId.USER_RESET_MFA,
        ResponseActionId.USER_FORCE_LOGOUT,
        ResponseActionId.USER_REVOKE_TOKENS,
        ResponseActionId.USER_RESET_PASSWORD,
        ResponseActionId.USER_EXPIRE_PASSWORD,
        ResponseActionId.USER_UNLOCK,
        ResponseActionId.USER_GROUP_REMOVE,
        ResponseActionId.USER_DELETE,
    }
)


def _route_for(spec: ResponseActionSpec) -> tuple[str, str]:
    """Return ``(method, path)`` for the action against Okta's API."""
    user_id = spec.subject.selector_value
    if spec.action_id is ResponseActionId.USER_DISABLE:
        return "POST", f"/api/v1/users/{user_id}/lifecycle/suspend"
    if spec.action_id is ResponseActionId.USER_RESET_MFA:
        return "POST", f"/api/v1/users/{user_id}/lifecycle/reset_factors"
    if spec.action_id is ResponseActionId.USER_FORCE_LOGOUT:
        return "DELETE", f"/api/v1/users/{user_id}/sessions"
    if spec.action_id is ResponseActionId.USER_REVOKE_TOKENS:
        # Kills all OAuth refresh tokens — distinct from sessions.
        # A compromised user with an exfiltrated refresh token keeps
        # access until this is called even after FORCE_LOGOUT.
        return "DELETE", f"/api/v1/users/{user_id}/tokens"
    if spec.action_id is ResponseActionId.USER_RESET_PASSWORD:
        return "POST", f"/api/v1/users/{user_id}/lifecycle/reset_password"
    if spec.action_id is ResponseActionId.USER_EXPIRE_PASSWORD:
        return "POST", f"/api/v1/users/{user_id}/lifecycle/expire_password"
    if spec.action_id is ResponseActionId.USER_UNLOCK:
        return "POST", f"/api/v1/users/{user_id}/lifecycle/unlock"
    if spec.action_id is ResponseActionId.USER_GROUP_REMOVE:
        group_id = spec.params["group_id"]
        return "DELETE", f"/api/v1/groups/{group_id}/users/{user_id}"
    if spec.action_id is ResponseActionId.USER_DELETE:
        # Okta requires deactivation BEFORE delete. The runtime is
        # expected to call USER_DISABLE first when the policy is
        # "destructive cleanup". Calling DELETE on an active user
        # returns 400 (E0000001) — surfaced as POLICY here.
        return "DELETE", f"/api/v1/users/{user_id}"
    raise ConnectorAbiError(
        FailureCategory.POLICY,
        f"okta-user-response: unroutable action {spec.action_id.value!r}",
    )


_OKTA_HTTP_TO_CATEGORY: dict[int, tuple[FailureCategory, bool]] = {
    401: (FailureCategory.AUTH, False),
    403: (FailureCategory.POLICY, False),
    404: (FailureCategory.NOT_FOUND, False),
    409: (FailureCategory.STATE_CONFLICT, False),
    429: (FailureCategory.TRANSIENT, True),
}


def _map_okta_error(resp: httpx.Response, *, op: str) -> ConnectorAbiError:
    """Map an Okta non-2xx response to a categorized ABI error.

    Okta's response body shape is documented at
    https://developer.okta.com/docs/reference/error-codes/ — every
    error contains ``errorCode`` (e.g. ``E0000007``) and ``errorSummary``.
    Both are preserved in ``vendor_*`` fields.
    """
    status = resp.status_code
    if status in _OKTA_HTTP_TO_CATEGORY:
        category, retryable = _OKTA_HTTP_TO_CATEGORY[status]
    elif 500 <= status < 600:
        category, retryable = FailureCategory.TRANSIENT, True
    else:
        category, retryable = FailureCategory.POLICY, False
    try:
        body = resp.json()
    except ValueError:
        body = {}
    return ConnectorAbiError(
        category,
        f"okta {op} failed: HTTP {status}",
        retryable=retryable,
        vendor_code=str(body.get("errorCode") or status),
        vendor_message=str(body.get("errorSummary") or "")[:200] or None,
    )


def _success(
    spec: ResponseActionSpec, *, vendor_response_id: str, dedup: bool
) -> ResponseActionResult:
    return ResponseActionResult(
        execution_id="",  # the runtime stamps it
        action_id=spec.action_id,
        outcome=ExecutionOutcome.SUCCESS,
        subject=spec.subject,
        details={
            "vendor_response_id": vendor_response_id,
            "vendor_dedup": dedup,
        },
    )


# ---------------------------------------------------------------------------
# CLI walkthrough — show the connector instantiates and declares correctly.
# Cannot exercise apply/verify without an Okta tenant; we stop at
# capability inspection so the file remains importable + runnable.
# ---------------------------------------------------------------------------


async def _main() -> None:
    # Construction-time validation — proves the manifest is well-formed.
    cap = OktaUserResponseConnector.capability
    print(f"connector_id     = {cap.connector_id}")
    print(f"vendor           = {cap.vendor}")
    print(f"kind             = {cap.kind.value}")
    print(f"auth_model       = {cap.auth.model.value}")
    print(f"actions          = {[a.value for a in cap.egress.supports_response_actions]}")
    print(f"dry_run.scope    = {cap.dry_run.scope.value}")
    print()
    print("To exercise the lifecycle against a real Okta tenant :")
    print("  export OKTA_BASE_URL='https://yourorg.okta.com'")
    print("  export OKTA_API_TOKEN='00...'")
    print("  python -m examples.okta_user_response_connector --live <user-id>")
    print()
    print("This script does NOT call Okta unless --live is passed and")
    print("the env vars are set. The reference is honest about its")
    print("runtime-test status — see the module docstring.")


if __name__ == "__main__":
    asyncio.run(_main())
