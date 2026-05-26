"""Canonical action metadata — the single source of truth for the
catalog of canonical response actions.

Each :class:`ResponseActionId` is paired here with its operational
metadata : family, reversibility, default approval policy, reviewer
count, and (optionally) the JSON Schema describing its required
``params``. Both runtimes and adopters read this table — the
runtime's approval gate derives its policy defaults from it,
conformance tooling validates connector capability declarations
against it, and the catalog audits in
``docs/canon-migration/`` serve as the human-readable narrative.

Why this exists as a structured registry instead of prose :
without it, the runtime had to maintain its own copy of "which
actions are destructive" (see the prior ``StaticPolicyResolver.
DEFAULT_MAP`` in the backend, since refactored to derive from this
table). That created drift — the spec said one thing in prose and
the runtime classified another in code. The registry closes that
gap : changes to reversibility or approval defaults flow from one
edit here to every consumer.

Adding a new ResponseActionId requires :

1. Add the enum value in :mod:`warlog_spec.provider_abi`.
2. Add an :class:`ActionMeta` entry here.
3. Update the four JSON schemas (``response-action-spec.json`` etc.)
4. If the action takes required params, add a JSON Schema at
   ``warlog-spec/schemas/action-params/<action>.json`` and reference
   it via ``params_schema_ref``.
5. Update ``warlog-spec/schemas/action-catalog.json`` for cross-
   language consumers (manual lockstep with this file today;
   programmatic export planned).
"""

from __future__ import annotations

from typing import NamedTuple

from warlog_spec.provider_abi import (
    ApprovalLevel,
    ResponseActionId,
    ResponseActionReversibility,
)


class ActionMeta(NamedTuple):
    """Canonical metadata for a single :class:`ResponseActionId`."""

    action_id: ResponseActionId
    family: str  # "identity" | "device" | "network" | "email" | "workflow"
    reversibility: ResponseActionReversibility
    default_approval: ApprovalLevel
    default_reviewers: int
    params_schema_ref: str | None
    summary: str


# =============================================================================
# Catalog — 35 actions
#
# Reversibility / approval defaults match the corrected classification
# in docs/canon-migration/14-reversibility-audit.md. Approval defaults
# follow the doctrine surfaced in that document :
#   REVERSIBLE  → analyst (auto-execute permitted in low-friction mode)
#   DISRUPTIVE  → senior  (gated even though inverse exists ; in-flight
#                          state lost matters)
#   DESTRUCTIVE → senior  (or manager for irreversible-irreversible
#                          like user.delete / cert.revoke / file.delete)
#                          + dry-run preview strongly recommended
#   VARIES      → analyst by default ; runtime overrides on a per-
#                 playbook basis.
# =============================================================================


_ENTRIES: tuple[ActionMeta, ...] = (
    # --- Device family ------------------------------------------------
    ActionMeta(
        ResponseActionId.HOST_ISOLATE,
        "device",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Isolate a host from the network (containment).",
    ),
    ActionMeta(
        ResponseActionId.HOST_UNISOLATE,
        "device",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Lift host network isolation.",
    ),
    ActionMeta(
        ResponseActionId.HOST_RESTART,
        "device",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Reboot the host (in-memory state lost).",
    ),
    ActionMeta(
        ResponseActionId.HOST_COLLECT_ARTIFACTS,
        "device",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        "action-params/host.collect_artifacts.json",
        "Pull a file or memory dump for forensics.",
    ),
    ActionMeta(
        ResponseActionId.PROCESS_KILL,
        "device",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Kill a running process (orphans children, releases handles).",
    ),
    ActionMeta(
        ResponseActionId.PROCESS_SUSPEND,
        "device",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Suspend a running process (resumable).",
    ),
    ActionMeta(
        ResponseActionId.FILE_QUARANTINE,
        "device",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Move a file to vendor quarantine (releasable).",
    ),
    ActionMeta(
        ResponseActionId.FILE_DELETE,
        "device",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.MANAGER,
        2,
        None,
        "Permanently delete a file (modulo out-of-band backups).",
    ),
    ActionMeta(
        ResponseActionId.HASH_BLOCK,
        "device",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Add a SHA256 to fleet-wide prevention.",
    ),
    # --- Identity family ----------------------------------------------
    ActionMeta(
        ResponseActionId.USER_DISABLE,
        "identity",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Suspend a user (work-in-progress lost).",
    ),
    ActionMeta(
        ResponseActionId.USER_FORCE_LOGOUT,
        "identity",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Terminate active user sessions (no un-logout).",
    ),
    ActionMeta(
        ResponseActionId.USER_RESET_MFA,
        "identity",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Remove enrolled MFA factors (must re-enroll).",
    ),
    ActionMeta(
        ResponseActionId.USER_REVOKE_TOKENS,
        "identity",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Invalidate all OAuth/refresh tokens.",
    ),
    ActionMeta(
        ResponseActionId.USER_RESET_PASSWORD,
        "identity",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Force admin-initiated password reset.",
    ),
    ActionMeta(
        ResponseActionId.USER_EXPIRE_PASSWORD,
        "identity",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Force password change at next login.",
    ),
    ActionMeta(
        ResponseActionId.USER_UNLOCK,
        "identity",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Clear a user lockout state.",
    ),
    ActionMeta(
        ResponseActionId.USER_GROUP_REMOVE,
        "identity",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        "action-params/user.group_remove.json",
        "Remove user from a (typically privileged) group.",
    ),
    ActionMeta(
        ResponseActionId.USER_DELETE,
        "identity",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.MANAGER,
        2,
        None,
        "Permanently delete a user account.",
    ),
    # --- Email family -------------------------------------------------
    ActionMeta(
        ResponseActionId.EMAIL_QUARANTINE,
        "email",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Move a delivered email to quarantine.",
    ),
    ActionMeta(
        ResponseActionId.EMAIL_RECALL,
        "email",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Pull a delivered email from recipient inbox (destroys their view).",
    ),
    ActionMeta(
        ResponseActionId.EMAIL_RELEASE,
        "email",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Release a quarantined message back to inbox.",
    ),
    ActionMeta(
        ResponseActionId.EMAIL_BLOCK_SENDER,
        "email",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Add a sender (email or domain) to the tenant blocklist.",
    ),
    ActionMeta(
        ResponseActionId.EMAIL_UNBLOCK_SENDER,
        "email",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Remove a sender from the tenant blocklist.",
    ),
    # --- Network family -----------------------------------------------
    ActionMeta(
        ResponseActionId.IP_BLOCK,
        "network",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Block an IP at the network perimeter.",
    ),
    ActionMeta(
        ResponseActionId.IP_UNBLOCK,
        "network",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Remove an IP from the network blocklist.",
    ),
    ActionMeta(
        ResponseActionId.DOMAIN_BLOCK,
        "network",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Block a domain at the network perimeter.",
    ),
    ActionMeta(
        ResponseActionId.DOMAIN_UNBLOCK,
        "network",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Remove a domain from the network blocklist.",
    ),
    ActionMeta(
        ResponseActionId.URL_BLOCK,
        "network",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Block a URL at the network perimeter.",
    ),
    ActionMeta(
        ResponseActionId.URL_UNBLOCK,
        "network",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Remove a URL from the network blocklist.",
    ),
    ActionMeta(
        ResponseActionId.HASH_UNBLOCK,
        "network",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Remove a SHA256 from fleet-wide prevention.",
    ),
    ActionMeta(
        ResponseActionId.SESSION_TERMINATE,
        "network",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        "action-params/session.terminate.json",
        "Drop an active TCP/UDP flow or VPN/ZTNA tunnel.",
    ),
    ActionMeta(
        ResponseActionId.CERT_REVOKE,
        "network",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.MANAGER,
        2,
        None,
        "Revoke a certificate via CRL/OCSP (must issue new cert).",
    ),
    # --- Compute / device extension (cloud audit) ---------------------
    ActionMeta(
        ResponseActionId.HOST_STOP,
        "device",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Stop a compute instance (in-memory state lost, disk preserved).",
    ),
    ActionMeta(
        ResponseActionId.HOST_START,
        "device",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Start a stopped compute instance (inverse of host.stop).",
    ),
    ActionMeta(
        ResponseActionId.HOST_DELETE,
        "device",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.MANAGER,
        2,
        None,
        "Permanently terminate a compute instance.",
    ),
    # --- IAM family (cloud audit) -------------------------------------
    ActionMeta(
        ResponseActionId.IAM_ROLE_DETACH,
        "iam",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        "action-params/iam.role_detach.json",
        "Detach an IAM role/policy from a principal (in-flight assumed sessions live to expiry).",
    ),
    ActionMeta(
        ResponseActionId.IAM_ROLE_ATTACH,
        "iam",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        "action-params/iam.role_detach.json",
        "Attach an IAM role/policy to a principal (inverse of iam.role_detach).",
    ),
    ActionMeta(
        ResponseActionId.IAM_CREDENTIALS_DISABLE,
        "iam",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        "action-params/iam.credentials_disable.json",
        "Disable an access key / service account credential.",
    ),
    ActionMeta(
        ResponseActionId.IAM_CREDENTIALS_ENABLE,
        "iam",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        "action-params/iam.credentials_disable.json",
        "Re-enable a disabled credential (inverse of iam.credentials_disable).",
    ),
    ActionMeta(
        ResponseActionId.IAM_CREDENTIALS_ROTATE,
        "iam",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.SENIOR,
        1,
        "action-params/iam.credentials_disable.json",
        "Rotate credentials (old credential gone, consumers must refresh).",
    ),
    # --- Key/secret family (cloud audit) ------------------------------
    ActionMeta(
        ResponseActionId.KEY_DISABLE,
        "key",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Disable a KMS key (encrypted data inaccessible until re-enabled).",
    ),
    ActionMeta(
        ResponseActionId.KEY_ENABLE,
        "key",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Re-enable a disabled KMS key (inverse of key.disable).",
    ),
    ActionMeta(
        # Cloud KMS rotation is version-add semantics : a new key
        # version becomes primary for new encrypts, old versions
        # remain enabled for decrypt (AWS, Azure, GCP all behave
        # this way). No operational disruption — old encrypted
        # data stays decryptable, no consumer "breaks". Hence
        # REVERSIBLE, not DISRUPTIVE.
        ResponseActionId.KEY_ROTATE,
        "key",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Rotate a KMS key (version-add ; old versions remain valid for decrypt).",
    ),
    ActionMeta(
        ResponseActionId.KEY_SCHEDULE_DELETION,
        "key",
        ResponseActionReversibility.DESTRUCTIVE,
        ApprovalLevel.MANAGER,
        2,
        "action-params/key.schedule_deletion.json",
        "Schedule a KMS key for permanent deletion after a cooldown.",
    ),
    # --- Storage family (cloud audit) ---------------------------------
    ActionMeta(
        ResponseActionId.BUCKET_LOCKDOWN,
        "storage",
        ResponseActionReversibility.DISRUPTIVE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Deny all public/external access to a bucket (active consumers break, reversible).",
    ),
    ActionMeta(
        # Semantic note : bucket.unlock removes the lockdown
        # ARTIFACTS (deny policy + public-access block) imposed by
        # bucket.lockdown. It does NOT restore any pre-lockdown
        # policy that may have existed — that would require the
        # connector to snapshot prior state, which is a separate
        # capability not modelled here. Orchestrators that need to
        # re-apply a specific policy after unlock issue that as a
        # follow-up step. The same "remove the action's artifacts"
        # semantic is shared by host.unisolate, ip.unblock, etc.
        ResponseActionId.BUCKET_UNLOCK,
        "storage",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.SENIOR,
        1,
        None,
        "Remove lockdown artifacts imposed by bucket.lockdown (does not restore prior policy).",
    ),
    # --- Workflow family ----------------------------------------------
    ActionMeta(
        ResponseActionId.ALERT_ACKNOWLEDGE,
        "workflow",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.NONE,
        0,
        None,
        "Acknowledge an alert (auto-executable).",
    ),
    ActionMeta(
        ResponseActionId.CASE_UPDATE_STATUS,
        "workflow",
        ResponseActionReversibility.REVERSIBLE,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Update the status of a case.",
    ),
    ActionMeta(
        ResponseActionId.PLAYBOOK_TRIGGER,
        "workflow",
        ResponseActionReversibility.VARIES,
        ApprovalLevel.ANALYST,
        1,
        None,
        "Trigger a playbook (reversibility depends on body).",
    ),
)


# Sanity check at import — duplicate detection BEFORE building the dict.
# A dict comprehension would silently overwrite duplicates, so an
# accidental double-entry (typo, copy-paste from another action) would
# produce inconsistent behaviour : ``ACTION_CATALOG[id]`` returns the
# last entry, but the convenience helpers below iterate ``_ENTRIES``
# directly and would visit BOTH copies. Fail fast instead.
_seen: list[ResponseActionId] = [e.action_id for e in _ENTRIES]
_dupes = sorted({a.value for a in _seen if _seen.count(a) > 1})
if _dupes:
    raise RuntimeError(
        f"action_catalog has duplicate entries for: {_dupes}"
    )
del _seen, _dupes


ACTION_CATALOG: dict[ResponseActionId, ActionMeta] = {e.action_id: e for e in _ENTRIES}


# Every ResponseActionId has exactly one catalog entry. If a future
# enum addition forgets to register here, the import explodes —
# failing fast is the desired UX.
_missing = set(ResponseActionId) - set(ACTION_CATALOG)
if _missing:
    raise RuntimeError(
        f"action_catalog is missing entries for: {sorted(a.value for a in _missing)}"
    )
del _missing


# Convenience accessors — derived views the runtime can consume
# without re-implementing the table walk each time.


def actions_by_family(family: str) -> list[ResponseActionId]:
    """List actions belonging to the requested family."""
    return [meta.action_id for meta in _ENTRIES if meta.family == family]


def actions_by_reversibility(
    reversibility: ResponseActionReversibility,
) -> list[ResponseActionId]:
    """List actions of a given reversibility class."""
    return [meta.action_id for meta in _ENTRIES if meta.reversibility is reversibility]


def default_approval_for(action_id: ResponseActionId) -> tuple[ApprovalLevel, int]:
    """Return ``(approval_level, reviewer_count)`` for an action.

    Runtimes derive their policy defaults from this. Tenant overrides
    layer ON TOP of these defaults — they don't replace them.
    """
    meta = ACTION_CATALOG[action_id]
    return meta.default_approval, meta.default_reviewers


class ParamsValidationError(Exception):
    """Raised when ``ResponseActionSpec.params`` violates the canonical
    schema for the action.

    Carries the list of validation messages so the caller (typically
    the runner) can map them to a :class:`ConnectorAbiError` with
    category ``POLICY`` and surface the precise field that failed in
    the audit row.
    """

    def __init__(self, action_id: ResponseActionId, errors: list[str]) -> None:
        super().__init__(
            f"params for {action_id.value} are invalid: " + " ; ".join(errors)
        )
        self.action_id = action_id
        self.errors = errors


def load_params_schema(action_id: ResponseActionId) -> dict[str, object] | None:
    """Return the JSON Schema for an action's params, or ``None`` if
    the action has no canonical params schema.

    Schemas are shipped inside the package at
    ``warlog_spec/_schemas/action-params/<action>.json`` so the package
    is self-contained — no filesystem lookup of the surrounding monorepo
    is required at runtime.
    """
    meta = ACTION_CATALOG.get(action_id)
    if meta is None or meta.params_schema_ref is None:
        return None
    import json
    from importlib.resources import files

    # ``params_schema_ref`` is a relative path under ``warlog-spec/schemas/``,
    # e.g. ``action-params/host.collect_artifacts.json``. Inside the
    # package the schemas live under ``warlog_spec/_schemas/<same path>``.
    resource = files("warlog_spec").joinpath("_schemas").joinpath(meta.params_schema_ref)
    with resource.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_params(
    action_id: ResponseActionId, params: dict[str, object]
) -> None:
    """Validate ``params`` against the action's canonical schema.

    No-op if the action has no ``params_schema_ref`` — connectors are
    free to accept any vendor-specific keys for those actions.

    Raises :class:`ParamsValidationError` on schema violation. Requires
    the optional ``jsonschema`` dependency: install with
    ``pip install warlog-spec[verify]`` (or rely on the backend's
    transitive dep, which pins ``warlog-spec[verify]`` explicitly).

    The caller (typically the runner) catches this and surfaces a
    :class:`ConnectorAbiError` with category ``POLICY`` so the audit
    row records WHICH field violated the canonical contract — that's
    the operational difference between "the connector validated late"
    and "the runtime caught it before the connector ever saw the
    request".
    """
    schema = load_params_schema(action_id)
    if schema is None:
        return  # action has no canonical params schema
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError(
            "params validation requires `pip install warlog-spec[verify]`"
        ) from exc
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(params), key=lambda e: e.path)
    if errors:
        messages = [
            f"{'.'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
            for e in errors
        ]
        raise ParamsValidationError(action_id, messages)


def to_json_manifest() -> dict[str, object]:
    """Return the canonical JSON manifest shape derived from the registry.

    This is the source of truth for ``warlog-spec/schemas/action-catalog.json``.
    A sync test (``test_action_catalog_json_in_sync_with_python_registry``)
    guards drift between the two artifacts ; running this module as
    ``python -m warlog_spec.action_catalog`` writes the regenerated JSON
    to stdout for the maintainer to commit.

    Cross-language SDKs (Go, TS) consume the JSON file directly. The
    Python registry is the authoring side ; the JSON is a derivation.
    """
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://3noP.github.io/warlog-spec/schemas/draft/action-catalog.json",
        "title": "Warlog Spec — canonical action catalog",
        "description": (
            "Per-action metadata (family, reversibility, default approval, "
            "default reviewers, optional params schema). Generated from "
            "warlog_spec.action_catalog.to_json_manifest()."
        ),
        "spec_version": "1.0",
        "actions": {
            meta.action_id.value: _meta_to_json(meta) for meta in _ENTRIES
        },
    }


def _meta_to_json(meta: ActionMeta) -> dict[str, object]:
    out: dict[str, object] = {
        "family": meta.family,
        "reversibility": meta.reversibility.value,
        "default_approval": meta.default_approval.value,
        "default_reviewers": meta.default_reviewers,
        "summary": meta.summary,
    }
    if meta.params_schema_ref is not None:
        out["params_schema_ref"] = meta.params_schema_ref
    return out


__all__ = [
    "ACTION_CATALOG",
    "ActionMeta",
    "ParamsValidationError",
    "actions_by_family",
    "actions_by_reversibility",
    "default_approval_for",
    "load_params_schema",
    "to_json_manifest",
    "validate_params",
]


if __name__ == "__main__":
    # Regeneration entry point :
    #   python -m warlog_spec.action_catalog > warlog-spec/schemas/action-catalog.json
    import json
    import sys

    json.dump(to_json_manifest(), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
