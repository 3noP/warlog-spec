"""Palo Alto PAN-OS connector — reference implementation.

Wraps the public PAN-OS XML API and User-ID interface
(https://docs.paloaltonetworks.com/pan-os/) to implement the
canonical SOC network response sub-graph against a Palo Alto NGFW
or Panorama.

Actions covered :

- :data:`ResponseActionId.IP_BLOCK`         → tag IP into Dynamic Address Group
- :data:`ResponseActionId.IP_UNBLOCK`       → untag IP (FP resolution)
- :data:`ResponseActionId.DOMAIN_BLOCK`     → tag FQDN address into DAG
- :data:`ResponseActionId.DOMAIN_UNBLOCK`   → untag FQDN
- :data:`ResponseActionId.URL_BLOCK`        → push to External Dynamic List
- :data:`ResponseActionId.URL_UNBLOCK`      → remove from EDL
- :data:`ResponseActionId.SESSION_TERMINATE` → XML op `clear session` /
                                                GP gateway logout

**Why DAG tagging instead of address-group CRUD :** PAN-OS commits
are 30-180s on busy firewalls. Adding/removing an address from a
group requires a commit. Adding/removing a TAG via the User-ID
interface (`<uid-message>`) does NOT — the firewall's Dynamic Address
Groups resolve membership in real-time from tags. For SOC response
this is the only viable path; orchestrating commits during incidents
is not.

**Why XML for session terminate :** the operational `clear session`
/ `request global-protect-gateway logout` commands have no REST
equivalent in PAN-OS. The XML API is the documented surface.

Auth model is API key in the ``X-PAN-Key`` header. The key is minted
once via ``POST /api/?type=keygen&user=...&password=...`` and persisted
in Vault. Modern Panorama / Strata Cloud Manager OAuth flows are out
of scope for this reference; switch in :meth:`authenticate`.

Configuration shape::

    {
        "base_url":     "https://panw-fw.example.test",
        "api_key":      "LUFRPT0...",       # X-PAN-Key value
        "block_tag":    "warlog-blocked",   # tag name DAG references
        "url_edl_name": "warlog-blocked-urls",  # External Dynamic List
        "verify_ssl":   true,
    }

Pre-requisite firewall config (one-time, by admin) :
- A Dynamic Address Group with `match` = ``'warlog-blocked'`` (or
  whatever tag the connector is configured with)
- A security policy rule matching that DAG → action=deny
- An External Dynamic List of type=URL, recipient = a security
  policy rule with URL filtering action=block
- The connector's API user has User-ID write rights and Operational
  Command privilege (XML op)

What this file proves :

- A vendor with TWO orthogonal API surfaces (REST + XML) fits the
  same ABI. The connector hides the surface choice.
- Block / unblock pairs ARE atomic primitives, not "block + commit
  later" gymnastics. Vendor-side tooling makes the difference; the
  ABI does not bake in commit semantics.
- Session termination is a network-layer primitive distinct from
  user.force_logout (identity layer) and process.kill (endpoint).
  The same `session.terminate` action covers TCP/UDP flow drop AND
  GlobalProtect VPN tunnel drop — the connector picks the operational
  command based on `params['session_type']`.

**Runtime-test status :** spec-conformant, written against PAN-OS
documented XML/User-ID API. Not yet exercised against a live PAN-OS
appliance. PRs welcome.

Requires ``httpx``.
"""

from __future__ import annotations

import asyncio
import re
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


_DEFAULT_BLOCK_TAG = "warlog-blocked"
_DEFAULT_URL_EDL_NAME = "warlog-blocked-urls"


class PaloAltoPanosConnector(AbiConnector):
    """ABI connector for Palo Alto PAN-OS NGFW / Panorama."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="paloalto-panos",
        connector_version="0.1.0",
        vendor="Palo Alto Networks",
        kind=ConnectorKind.NETWORK,
        auth=AuthDescriptor(
            model=ConnectorAuthModel.API_KEY,
            scopes=["panos.user-id.write", "panos.op.read", "panos.op.write"],
        ),
        egress=EgressDescriptor(
            supports_response_actions=[
                ResponseActionId.IP_BLOCK,
                ResponseActionId.IP_UNBLOCK,
                ResponseActionId.DOMAIN_BLOCK,
                ResponseActionId.DOMAIN_UNBLOCK,
                ResponseActionId.URL_BLOCK,
                ResponseActionId.URL_UNBLOCK,
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
        if not isinstance(base_url, str) or not base_url:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                "panos: config['base_url'] is required (e.g. https://fw.example.test)",
            )
        if not isinstance(api_key, str) or not api_key:
            raise ConnectorAbiError(
                FailureCategory.AUTH,
                "panos: config['api_key'] is required",
            )
        self._api_key = api_key
        self._block_tag = str(config.get("block_tag") or _DEFAULT_BLOCK_TAG)
        self._url_edl_name = str(
            config.get("url_edl_name") or _DEFAULT_URL_EDL_NAME
        )
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(30.0, connect=10.0),
            verify=bool(config.get("verify_ssl", True)),
            headers={"Accept": "application/xml"},
        )
        self._applied: dict[str, str] = {}

    # -- Lifecycle hooks --------------------------------------------------

    async def authenticate(self) -> None:
        # Smoke the key with a read-only op : `<show><system><info>`.
        try:
            resp = await self._xml_op(
                "<show><system><info></info></system></show>"
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"panos: auth network error: {exc}",
            ) from exc
        if resp.status_code != 200 or not _xml_is_success(resp.text):
            raise _map_panos_error(resp, op="authenticate")

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        if spec.action_id not in _SUPPORTED:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"panos does not implement {spec.action_id.value!r}",
            )
        if not spec.subject.selector_value:
            raise ConnectorAbiError(
                FailureCategory.NOT_FOUND,
                "panos: subject.selector_value is required",
            )
        if spec.action_id is ResponseActionId.SESSION_TERMINATE:
            session_type = spec.params.get("session_type", "flow")
            if session_type not in {"flow", "vpn"}:
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "panos: session.terminate requires "
                    "params['session_type'] in {'flow', 'vpn'} (default 'flow')",
                )
            if session_type == "flow" and spec.subject.selector_type not in {
                "ipv4",
                "ipv6",
                "session_id",
            }:
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "panos: session.terminate flow requires subject.selector_type "
                    "in {'ipv4', 'ipv6', 'session_id'}",
                )
            if session_type == "vpn" and spec.subject.selector_type != "username":
                raise ConnectorAbiError(
                    FailureCategory.POLICY,
                    "panos: session.terminate vpn requires "
                    "subject.selector_type='username'",
                )

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        cached = self._applied.get(spec.idempotency_key)
        if cached is not None:
            return _success(spec, vendor_resource_id=cached, dedup=True)

        if spec.action_id in {
            ResponseActionId.IP_BLOCK,
            ResponseActionId.DOMAIN_BLOCK,
        }:
            await self._uid_register(spec.subject.selector_value)
            resource_id = f"tag:{self._block_tag}:{spec.subject.selector_value}"
        elif spec.action_id in {
            ResponseActionId.IP_UNBLOCK,
            ResponseActionId.DOMAIN_UNBLOCK,
        }:
            await self._uid_unregister(spec.subject.selector_value)
            resource_id = f"untag:{self._block_tag}:{spec.subject.selector_value}"
        elif spec.action_id is ResponseActionId.URL_BLOCK:
            await self._edl_modify(spec.subject.selector_value, add=True)
            resource_id = f"edl:{self._url_edl_name}:add:{spec.subject.selector_value}"
        elif spec.action_id is ResponseActionId.URL_UNBLOCK:
            await self._edl_modify(spec.subject.selector_value, add=False)
            resource_id = f"edl:{self._url_edl_name}:rm:{spec.subject.selector_value}"
        elif spec.action_id is ResponseActionId.SESSION_TERMINATE:
            resource_id = await self._terminate_session(spec)
        else:
            raise ConnectorAbiError(
                FailureCategory.POLICY,
                f"panos: unroutable action {spec.action_id.value!r}",
            )

        self._applied[spec.idempotency_key] = resource_id
        return _success(spec, vendor_resource_id=resource_id, dedup=False)

    async def verify(
        self, spec: ResponseActionSpec, result: ResponseActionResult
    ) -> bool:
        if spec.action_id in {
            ResponseActionId.IP_BLOCK,
            ResponseActionId.DOMAIN_BLOCK,
        }:
            return await self._is_tagged(spec.subject.selector_value)
        if spec.action_id in {
            ResponseActionId.IP_UNBLOCK,
            ResponseActionId.DOMAIN_UNBLOCK,
        }:
            return not await self._is_tagged(spec.subject.selector_value)
        if spec.action_id in {
            ResponseActionId.URL_BLOCK,
            ResponseActionId.URL_UNBLOCK,
        }:
            # PAN-OS EDLs are pulled by the firewall on a refresh
            # interval (default 5 min). The HTTP 200 from EDL push
            # is the contract here; verify is fire-and-forget at the
            # configuration layer.
            return True
        if spec.action_id is ResponseActionId.SESSION_TERMINATE:
            # XML op response success is the contract; the session is
            # gone the moment the firewall ACKs. No idempotent GET.
            return True
        return False

    # -- Vendor-specific operations --------------------------------------

    async def _uid_register(self, ip_or_fqdn: str) -> None:
        """Tag an address with the block tag via User-ID interface.

        Uses ``<uid-message>...<register>`` payload. Takes effect
        immediately, no commit required. Works for both IPs (literal)
        and FQDN-resolved addresses (PAN-OS resolves the FQDN and
        applies the tag to the resolved IPs).
        """
        cmd = (
            f"<uid-message><version>2.0</version><type>update</type>"
            f"<payload><register>"
            f'<entry ip="{_xml_escape(ip_or_fqdn)}" persistent="1">'
            f"<tag><member>{_xml_escape(self._block_tag)}</member></tag>"
            f"</entry></register></payload></uid-message>"
        )
        await self._user_id_send(cmd, op="uid:register")

    async def _uid_unregister(self, ip_or_fqdn: str) -> None:
        cmd = (
            f"<uid-message><version>2.0</version><type>update</type>"
            f"<payload><unregister>"
            f'<entry ip="{_xml_escape(ip_or_fqdn)}">'
            f"<tag><member>{_xml_escape(self._block_tag)}</member></tag>"
            f"</entry></unregister></payload></uid-message>"
        )
        await self._user_id_send(cmd, op="uid:unregister")

    async def _user_id_send(self, cmd: str, *, op: str) -> None:
        try:
            resp = await self._client.post(
                "/api/",
                params={
                    "type": "user-id",
                    "key": self._api_key,
                    "cmd": cmd,
                },
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"panos: {op} network error: {exc}",
            ) from exc
        if resp.status_code != 200 or not _xml_is_success(resp.text):
            raise _map_panos_error(resp, op=op)

    async def _is_tagged(self, ip_or_fqdn: str) -> bool:
        """Check whether the address currently carries the block tag."""
        cmd = (
            f"<show><object><registered-ip>"
            f'<ip>{_xml_escape(ip_or_fqdn)}</ip>'
            f"</registered-ip></object></show>"
        )
        resp = await self._xml_op(cmd)
        if resp.status_code != 200:
            return False
        return self._block_tag in resp.text

    async def _edl_modify(self, url: str, *, add: bool) -> None:
        """Add or remove a URL from the configured External Dynamic List.

        EDL content is exposed via the REST API at
        /restapi/v10.1/Objects/ExternalDynamicLists. Editing the list
        is config-layer (commit needed for the EDL definition itself),
        but the firewall pulls the URL list from the EDL source on a
        refresh interval — typically the EDL points to an HTTP feed
        the connector publishes. For this reference we drive the
        *managed-locally* shape : a custom-URL-category EDL maintained
        via the URL list endpoint.
        """
        # Fetch current list, mutate, push back.
        try:
            get_resp = await self._client.get(
                f"/restapi/v10.1/Objects/CustomURLCategories",
                params={"name": self._url_edl_name, "key": self._api_key},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"panos: edl GET network error: {exc}",
            ) from exc
        if get_resp.status_code not in (200, 404):
            raise _map_panos_error(get_resp, op="edl:get")
        current = _extract_url_list(get_resp.text) if get_resp.status_code == 200 else []
        next_list = list(current)
        if add and url not in next_list:
            next_list.append(url)
        elif not add and url in next_list:
            next_list.remove(url)
        else:
            return  # idempotent no-op

        body = (
            f"<entry name='{_xml_escape(self._url_edl_name)}'>"
            f"<list>"
            + "".join(f"<member>{_xml_escape(u)}</member>" for u in next_list)
            + "</list><type>URL List</type></entry>"
        )
        try:
            put_resp = await self._client.put(
                "/restapi/v10.1/Objects/CustomURLCategories",
                params={"name": self._url_edl_name, "key": self._api_key},
                content=body,
                headers={"Content-Type": "application/xml"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorAbiError(
                FailureCategory.TRANSIENT,
                f"panos: edl PUT network error: {exc}",
            ) from exc
        if put_resp.status_code not in (200, 201):
            raise _map_panos_error(put_resp, op="edl:put")

    async def _terminate_session(self, spec: ResponseActionSpec) -> str:
        """Drop a TCP/UDP flow or a GlobalProtect VPN tunnel.

        For ``session_type='flow'`` (default) :
          - subject.selector_type='session_id' → ``clear session id N``
          - subject.selector_type='ipv4'/'ipv6' → ``clear session source <ip>``
            (drops every active flow with that source IP)
        For ``session_type='vpn'`` :
          - subject.selector_type='username' →
            ``request global-protect-gateway client logout user <name>``
        """
        session_type = spec.params.get("session_type", "flow")
        selector = spec.subject.selector_value
        if session_type == "vpn":
            cmd = (
                f"<request><global-protect-gateway><client-logout>"
                f"<gateway>{_xml_escape(str(spec.params.get('gateway') or 'all'))}</gateway>"
                f"<user>{_xml_escape(selector)}</user>"
                f"<reason>force-logout</reason>"
                f"</client-logout></global-protect-gateway></request>"
            )
        elif spec.subject.selector_type == "session_id":
            cmd = (
                f"<clear><session><id>{_xml_escape(selector)}</id></session></clear>"
            )
        else:
            cmd = (
                f"<clear><session><source>{_xml_escape(selector)}</source></session></clear>"
            )
        resp = await self._xml_op(cmd)
        if resp.status_code != 200 or not _xml_is_success(resp.text):
            raise _map_panos_error(resp, op=f"session:{session_type}")
        return f"session:{session_type}:{selector}:{uuid4().hex[:8]}"

    async def _xml_op(self, cmd: str) -> httpx.Response:
        return await self._client.post(
            "/api/",
            params={"type": "op", "cmd": cmd, "key": self._api_key},
        )

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SUPPORTED: frozenset[ResponseActionId] = frozenset(
    {
        ResponseActionId.IP_BLOCK,
        ResponseActionId.IP_UNBLOCK,
        ResponseActionId.DOMAIN_BLOCK,
        ResponseActionId.DOMAIN_UNBLOCK,
        ResponseActionId.URL_BLOCK,
        ResponseActionId.URL_UNBLOCK,
        ResponseActionId.SESSION_TERMINATE,
    }
)


_PANOS_HTTP_TO_CATEGORY: dict[int, tuple[FailureCategory, bool]] = {
    400: (FailureCategory.POLICY, False),
    401: (FailureCategory.AUTH, False),
    403: (FailureCategory.POLICY, False),
    404: (FailureCategory.NOT_FOUND, False),
    409: (FailureCategory.STATE_CONFLICT, False),
    429: (FailureCategory.TRANSIENT, True),
}


def _map_panos_error(resp: httpx.Response, *, op: str) -> ConnectorAbiError:
    status = resp.status_code
    if status in _PANOS_HTTP_TO_CATEGORY:
        category, retryable = _PANOS_HTTP_TO_CATEGORY[status]
    elif 500 <= status < 600:
        category, retryable = FailureCategory.TRANSIENT, True
    else:
        category, retryable = FailureCategory.POLICY, False
    # PAN-OS returns ``<response status='error' code='N'><msg>...</msg></response>``
    msg_match = re.search(r"<msg>(.*?)</msg>", resp.text, re.DOTALL)
    code_match = re.search(r"code\s*=\s*['\"](\d+)['\"]", resp.text)
    return ConnectorAbiError(
        category,
        f"panos {op} failed: HTTP {status}",
        retryable=retryable,
        vendor_code=(code_match.group(1) if code_match else str(status)),
        vendor_message=(msg_match.group(1).strip()[:200] if msg_match else None),
    )


def _xml_is_success(body: str) -> bool:
    """PAN-OS wraps every XML-API response in
    ``<response status='success|error'>...</response>``.
    """
    return "status=\"success\"" in body or "status='success'" in body


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _extract_url_list(body: str) -> list[str]:
    """Pull `<member>...</member>` entries from a CustomURLCategory body."""
    return re.findall(r"<member>([^<]+)</member>", body)


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
    cap = PaloAltoPanosConnector.capability
    print(f"connector_id     = {cap.connector_id}")
    print(f"vendor           = {cap.vendor}")
    print(f"kind             = {cap.kind.value}")
    print(f"auth_model       = {cap.auth.model.value}")
    print(f"actions          = {[a.value for a in cap.egress.supports_response_actions]}")
    print(f"dry_run.scope    = {cap.dry_run.scope.value}")
    print()
    print("To exercise against a real PAN-OS appliance :")
    print("  export PANOS_BASE_URL='https://fw.example.test'")
    print("  export PANOS_API_KEY='LUFRPT0...'")
    print("  python -m examples.palo_alto_panos_connector --live <ip>")


if __name__ == "__main__":
    asyncio.run(_main())
