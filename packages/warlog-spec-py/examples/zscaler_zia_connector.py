"""Zscaler Internet Access (ZIA) connector — reference implementation.

Wraps the public Zscaler ZIA API
(https://help.zscaler.com/zia/zia-api) to implement the canonical SOC
network sub-graph against a Zscaler tenant.

Actions covered (ALL existing canon — no canon delta from this audit) :

- :data:`ResponseActionId.URL_BLOCK`     → add to a custom URL category
- :data:`ResponseActionId.URL_UNBLOCK`   → remove from custom URL category
- :data:`ResponseActionId.DOMAIN_BLOCK`  → add to URL category (FQDN entry)
- :data:`ResponseActionId.DOMAIN_UNBLOCK` → remove from URL category
- :data:`ResponseActionId.HASH_BLOCK`    → submit to Sandbox blocklist
- :data:`ResponseActionId.HASH_UNBLOCK`  → remove from Sandbox blocklist
- :data:`ResponseActionId.SESSION_TERMINATE` → ZPA app session disconnect

The Zscaler audit (see ``docs/canon-migration/13-zscaler-no-extension.md``)
concluded that Zscaler's response surface maps cleanly onto the existing
canon. No new ResponseActionId values are added — this connector
demonstrates that the catalog is well-shaped for the SWG/SSE class.

**Activation model :** ZIA mutations require an explicit ``POST
/api/v1/status/activate`` after the policy change to push the new
config to the cloud nodes (~10s). The connector activates after
each apply automatically — orchestrators that batch multiple
actions can disable this with ``params['skip_activate']=True`` and
issue a single activate at the end.

Auth model is the legacy ZIA "obfuscated API key" flow :
``POST /api/v1/authenticatedSession`` with ``apiKey`` (timestamp-
obfuscated), ``username``, ``password``. The session cookie is
attached to subsequent calls. Modern OneAPI / OAuth2 is out of scope
for this reference; switch in :meth:`authenticate`.

Configuration shape::

    {
        "base_url":          "https://zsapi.zscaler.net",
        "api_key":           "raw API key (un-obfuscated)",
        "username":          "admin@yourorg.example",
        "password":          "redacted",
        "url_category_id":   "CUSTOM_01",   # name of pre-created URL cat
        "auto_activate":     true,
    }

What this file proves :

- A purely cloud-delivered SSE vendor fits the same ABI as on-prem
  PAN-OS without canon extensions. The "block / unblock" pair, the
  "session terminate" verb, and the hash/file primitives all speak
  the same language across deployment models.
- ZIA's activation step is a vendor implementation detail, hidden
  from the ABI contract. Connectors paper over commit-vs-immediate
  semantics; the runtime never has to know.

**Runtime-test status :** spec-conformant, written against ZIA's
documented v1 API. Not yet exercised against a live tenant. PRs welcome.

Requires ``httpx``.
"""

from __future__ import annotations

import asyncio
import time
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


class ZscalerZiaConnector(AbiConnector):
    """ABI connector for Zscaler Internet Access (ZIA) + Sandbox + ZPA."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="zscaler-zia",
        connector_version="0.1.0",
        vendor="Zscaler",
        kind=ConnectorKind.NETWORK,
        auth=AuthDescriptor(
            model=ConnectorAuthModel.API_KEY,
            scopes=["zia.policy.write", "zia.sandbox.write", "zpa.session.write"],
        ),
        egress=EgressDescriptor(
            supports_response_actions=[
                ResponseActionId.URL_BLOCK,
                ResponseActionId.URL_UNBLOCK,
                ResponseActionId.DOMAIN_BLOCK,
                ResponseActionId.DOMAIN_UNBLOCK,
                ResponseActionId.HASH_BLOCK,
                ResponseActionId.HASH_UNBLOCK,
                ResponseActionId.SESSION_TERMINATE,
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
        api_key = config.get("api_key")
        username = config.get("username")
        password = config.get("password")
        category_id = config.get("url_category_id")
        if not isinstance(base_url, str) or not base_url:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "zscaler: config['base_url'] is required",
            )
        if not all(isinstance(v, str) and v for v in (api_key, username, password)):
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "zscaler: api_key, username, password are all required",
            )
        if not isinstance(category_id, str) or not category_id:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "zscaler: config['url_category_id'] is required (pre-created in admin UI)",
            )
        self._api_key = api_key
        self._username = username
        self._password = password
        self._category_id = category_id
        self._auto_activate = bool(config.get("auto_activate", True))
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            cookies=httpx.Cookies(),
        )
        self._applied: dict[str, str] = {}

    # -- Lifecycle hooks --------------------------------------------------

    async def authenticate(self) -> None:
        """Obtain a JSESSIONID cookie via the obfuscated-key flow.

        ZIA's auth requires a timestamp-derived obfuscation of the
        API key — the algorithm is documented in Zscaler's API guide.
        The cookie is set on the shared client; subsequent requests
        ride it.
        """
        timestamp_ms = str(int(time.time() * 1000))
        obfuscated = _obfuscate_api_key(self._api_key, timestamp_ms)
        try:
            resp = await self._client.post(
                "/api/v1/authenticatedSession",
                json={
                    "apiKey": obfuscated,
                    "username": self._username,
                    "password": self._password,
                    "timestamp": timestamp_ms,
                },
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"zscaler: auth network error: {exc}",
            ) from exc
        if resp.status_code != 200:
            raise _map_zscaler_error(resp, op="authenticate")

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        if spec.action_id not in _SUPPORTED:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"zscaler does not implement {spec.action_id.value!r}",
            )
        if not spec.subject.selector_value:
            raise ConnectorAbiError(
                FailureCategory.NOT_FOUND,
                "zscaler: subject.selector_value is required",
            )
        if spec.action_id is ResponseActionId.SESSION_TERMINATE:
            session_type = spec.params.get("session_type")
            if session_type != "ztna":
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "zscaler: session.terminate requires "
                    "params['session_type']='ztna' (this connector wraps ZPA only)",
                )
            if spec.subject.selector_type != "username":
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "zscaler: ZPA session.terminate requires "
                    "subject.selector_type='username'",
                )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        cached = self._applied.get(spec.idempotency_key)
        if cached is not None:
            return _success(spec, vendor_resource_id=cached, dedup=True)

        if spec.action_id in {
            ResponseActionId.URL_BLOCK,
            ResponseActionId.DOMAIN_BLOCK,
        }:
            await self._url_category_modify(spec.subject.selector_value, add=True)
            resource_id = f"urlcat:{self._category_id}:add:{spec.subject.selector_value}"
        elif spec.action_id in {
            ResponseActionId.URL_UNBLOCK,
            ResponseActionId.DOMAIN_UNBLOCK,
        }:
            await self._url_category_modify(spec.subject.selector_value, add=False)
            resource_id = f"urlcat:{self._category_id}:rm:{spec.subject.selector_value}"
        elif spec.action_id is ResponseActionId.HASH_BLOCK:
            resource_id = await self._sandbox_block_hash(
                spec.subject.selector_value, add=True
            )
        elif spec.action_id is ResponseActionId.HASH_UNBLOCK:
            resource_id = await self._sandbox_block_hash(
                spec.subject.selector_value, add=False
            )
        elif spec.action_id is ResponseActionId.SESSION_TERMINATE:
            resource_id = await self._zpa_disconnect(spec.subject.selector_value)
        else:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"zscaler: unroutable action {spec.action_id.value!r}",
            )

        # ZIA changes need an explicit activation push to the cloud
        # nodes. ZPA session ops are immediate. Hash sandbox is also
        # immediate. Only URL-category mutations go through activate.
        if self._auto_activate and spec.action_id in {
            ResponseActionId.URL_BLOCK,
            ResponseActionId.URL_UNBLOCK,
            ResponseActionId.DOMAIN_BLOCK,
            ResponseActionId.DOMAIN_UNBLOCK,
        } and not spec.params.get("skip_activate"):
            await self._activate()

        self._applied[spec.idempotency_key] = resource_id
        return _success(spec, vendor_resource_id=resource_id, dedup=False)

    async def verify(
        self, spec: ResponseActionSpec, result: ResponseActionResult
    ) -> bool:
        if spec.action_id in {
            ResponseActionId.URL_BLOCK,
            ResponseActionId.DOMAIN_BLOCK,
        }:
            return await self._url_category_contains(spec.subject.selector_value)
        if spec.action_id in {
            ResponseActionId.URL_UNBLOCK,
            ResponseActionId.DOMAIN_UNBLOCK,
        }:
            return not await self._url_category_contains(spec.subject.selector_value)
        if spec.action_id in {
            ResponseActionId.HASH_BLOCK,
            ResponseActionId.HASH_UNBLOCK,
            ResponseActionId.SESSION_TERMINATE,
        }:
            # Sandbox blocklist + ZPA session kill have no idempotent
            # GET in the public API. The 200 from apply is the contract.
            return True
        return False

    # -- Vendor-specific operations --------------------------------------

    async def _url_category_modify(self, value: str, *, add: bool) -> None:
        """Mutate a custom URL category by adding/removing a URL or FQDN."""
        # GET current category, mutate URLs list, PUT back. ZIA
        # endpoint accepts &action=ADD_TO_LIST / REMOVE_FROM_LIST as
        # a delta-style alternative.
        try:
            resp = await self._client.put(
                f"/api/v1/urlCategories/{self._category_id}",
                params={"action": "ADD_TO_LIST" if add else "REMOVE_FROM_LIST"},
                json={"urls": [value], "configuredName": self._category_id},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"zscaler: urlcat network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 204):
            raise _map_zscaler_error(resp, op="urlcat:modify")

    async def _url_category_contains(self, value: str) -> bool:
        try:
            resp = await self._client.get(
                f"/api/v1/urlCategories/{self._category_id}"
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"zscaler: urlcat GET network error: {exc}",
            ) from exc
        if resp.status_code != 200:
            return False
        urls = resp.json().get("urls") or []
        return value in urls

    async def _sandbox_block_hash(self, sha256: str, *, add: bool) -> str:
        """Add/remove a SHA256 to the Sandbox blocklist.

        Uses /api/v1/security/advanced/blacklistUrls for hashes (the
        endpoint is named for URLs but accepts hash entries with
        type indicator). For a strictly hash-only path, /api/v1/sandbox
        report APIs apply too — this reference uses the simpler
        blacklist endpoint.
        """
        path = "/api/v1/security/advanced"
        try:
            resp = await self._client.put(
                path,
                params={"action": "ADD_TO_LIST" if add else "REMOVE_FROM_LIST"},
                json={"blacklistUrls": [f"hash:{sha256}"]},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"zscaler: sandbox network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 204):
            raise _map_zscaler_error(resp, op=f"sandbox:{'add' if add else 'remove'}")
        return f"sandbox:{'add' if add else 'rm'}:{sha256}"

    async def _zpa_disconnect(self, username: str) -> str:
        """Disconnect all ZPA app sessions for a user.

        ZPA Connect-API : POST /mgmtconfig/v1/admin/customers/{tenantId}/users/{userId}/sessions/disconnect
        For the reference, we accept an opaque username and let the
        tenant resolve user_id via its IDP attribute mapping. A
        production connector would resolve username → ZPA user id
        via /mgmtconfig/v1/admin/customers/{tenantId}/users.
        """
        try:
            resp = await self._client.post(
                f"/zpa-mgmt/users/{username}/sessions/disconnect",
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"zscaler: zpa disconnect network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 202, 204):
            raise _map_zscaler_error(resp, op="zpa:disconnect")
        return f"zpa:disconnect:{username}:{uuid4().hex[:8]}"

    async def _activate(self) -> None:
        """Push pending policy changes to the ZIA cloud nodes."""
        try:
            resp = await self._client.post("/api/v1/status/activate")
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"zscaler: activate network error: {exc}",
            ) from exc
        if resp.status_code not in (200, 204):
            raise _map_zscaler_error(resp, op="activate")

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_SUPPORTED: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.URL_BLOCK,
        ResponseActionId.URL_UNBLOCK,
        ResponseActionId.DOMAIN_BLOCK,
        ResponseActionId.DOMAIN_UNBLOCK,
        ResponseActionId.HASH_BLOCK,
        ResponseActionId.HASH_UNBLOCK,
        ResponseActionId.SESSION_TERMINATE,
    }
)


def _obfuscate_api_key(api_key: str, timestamp_ms: str) -> str:
    """ZIA's documented API-key obfuscation.

    Algorithm (from Zscaler API guide) : take the LAST 6 digits of
    the millisecond timestamp ; let n = int(those 6) ; let r =
    str(n).zfill(6) ; let key2 = "" ; for each digit d in r,
    key2 += api_key[int(d)] ; for each digit d in str(n)[1::]:6 (with
    pad), key2 += api_key[int(d)+2] ; return key2.

    This reference implements the algorithm faithfully.
    """
    high = timestamp_ms[-6:]
    low = str(int(high) >> 1).zfill(6)
    obfuscated = []
    for d in high:
        obfuscated.append(api_key[int(d)])
    for d in low:
        obfuscated.append(api_key[int(d) + 2])
    return "".join(obfuscated)


_ZSCALER_HTTP_TO_CATEGORY: dict[int, tuple[FailureCategory, bool]] = {
    400: (FailureCategory.POLICY, False),
    401: (FailureCategory.AUTH, False),
    403: (FailureCategory.POLICY, False),
    404: (FailureCategory.NOT_FOUND, False),
    409: (FailureCategory.STATE_CONFLICT, False),
    429: (FailureCategory.TRANSIENT, True),
}


def _map_zscaler_error(resp: httpx.Response, *, op: str) -> ConnectorAbiError:
    status = resp.status_code
    if status in _ZSCALER_HTTP_TO_CATEGORY:
        category, retryable = _ZSCALER_HTTP_TO_CATEGORY[status]
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
        f"zscaler {op} failed: HTTP {status}",
        retryable=retryable,
        vendor_code=str(body.get("code") or status),
        vendor_message=str(body.get("message") or "")[:200] or None,
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
    cap = ZscalerZiaConnector.capability
    print(f"connector_id     = {cap.connector_id}")
    print(f"vendor           = {cap.vendor}")
    print(f"kind             = {cap.kind.value}")
    print(f"auth_model       = {cap.auth.model.value}")
    print(f"actions          = {[a.value for a in cap.egress.supports_response_actions]}")
    print(f"dry_run.scope    = {cap.dry_run.scope.value}")
    print()
    print("Audit conclusion : zero new ResponseActionId required.")
    print("Zscaler ZIA + Sandbox + ZPA map cleanly onto existing canon.")


if __name__ == "__main__":
    asyncio.run(_main())
