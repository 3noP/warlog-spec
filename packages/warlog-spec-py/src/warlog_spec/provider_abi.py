"""Provider ABI — typed Pydantic contract for connector response actions.

The Provider ABI is the equivalent of a Terraform provider protocol :
a stable contract by which a connector declares its capabilities,
authenticates, executes response actions, and reports failures.

Schemas in this module are published as JSON Schema in
``warlog-spec/schemas/provider-abi/``. Implementations in any language
must round-trip-validate against those schemas.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
import re
from typing import Annotated, Literal, Union

from pydantic import Field, model_validator

from warlog_spec._base import SpecModel

ABI_VERSION = "1.0"
HEX64_PATTERN = "^[0-9a-f]{64}$"
HEX_PATTERN = "^[0-9a-f]+$"


def _is_hex64(value: str) -> bool:
    return re.fullmatch(HEX64_PATTERN, value) is not None


# =============================================================================
# Enums — the canonical vocabulary
# =============================================================================


class ResponseActionId(StrEnum):
    """Catalog of canonical, vendor-neutral atomic response actions.

    Connectors declare which of these they implement via
    ``ConnectorCapability.egress.supports_response_actions``. New
    actions require an RFC and a MINOR spec bump.
    """

    HOST_ISOLATE = "host.isolate"
    HOST_UNISOLATE = "host.unisolate"
    PROCESS_KILL = "process.kill"
    PROCESS_SUSPEND = "process.suspend"
    FILE_QUARANTINE = "file.quarantine"
    FILE_DELETE = "file.delete"
    # --- Device family extension (additive within ABI 1.0) ------------
    # Justification : the original six miss restart, forensic
    # collection, and hash-based prevention — primitives every major
    # EDR (Falcon, Defender, SentinelOne, Carbon Black) exposes
    # explicitly. Cross-vendor verified before admission.
    # See docs/canon-migration/09-device-gap-audit.md.
    HOST_RESTART = "host.restart"
    HOST_COLLECT_ARTIFACTS = "host.collect_artifacts"
    HASH_BLOCK = "hash.block"
    # --- Network family extension (additive within ABI 1.0) -----------
    # Justification : the original three (ip/domain/url block) miss
    # their inverse (false-positive resolution / scoped exception
    # during triage), miss hash unblock for EDR symmetry, and miss
    # session termination (firewalls block new flows but existing
    # flows survive until reset). Palo Alto + Cisco Firepower +
    # Fortinet FortiGate + Check Point all expose these.
    # See docs/canon-migration/11-network-gap-audit.md.
    IP_UNBLOCK = "ip.unblock"
    DOMAIN_UNBLOCK = "domain.unblock"
    URL_UNBLOCK = "url.unblock"
    HASH_UNBLOCK = "hash.unblock"
    SESSION_TERMINATE = "session.terminate"
    # --- Email family extension (additive within ABI 1.0) -------------
    # Justification : original two (quarantine, recall) miss sender-
    # side actions and quarantine release. Proofpoint + M365 Defender
    # for Email + Mimecast + Cisco Email Security + Google Workspace
    # all expose these. See docs/canon-migration/12-email-gap-audit.md.
    EMAIL_BLOCK_SENDER = "email.block_sender"
    EMAIL_UNBLOCK_SENDER = "email.unblock_sender"
    EMAIL_RELEASE = "email.release"
    # --- Compute / device extension (cloud audit, additive) -----------
    HOST_STOP = "host.stop"
    HOST_START = "host.start"  # inverse of host.stop (audit 16)
    HOST_DELETE = "host.delete"
    # --- IAM family (cloud audit, additive) ---------------------------
    # Justification : cloud-IAM primitives are operationally distinct
    # from human-user identity primitives (the user.* family). A
    # service principal / machine identity has roles attached, access
    # keys / SAS tokens / service-account keys, and assumed-session
    # tokens. These need their own canonical actions because the IR
    # response shape differs from the user.* family. Cross-validated
    # against AWS IAM, Azure RBAC, and GCP IAM. See
    # docs/canon-migration/15-cloud-gap-audit.md.
    IAM_ROLE_DETACH = "iam.role_detach"
    IAM_ROLE_ATTACH = "iam.role_attach"  # inverse of iam.role_detach (audit 16)
    IAM_CREDENTIALS_DISABLE = "iam.credentials_disable"
    IAM_CREDENTIALS_ENABLE = "iam.credentials_enable"  # inverse (audit 16)
    IAM_CREDENTIALS_ROTATE = "iam.credentials_rotate"
    # --- Key/secret family (cloud audit, additive) --------------------
    KEY_DISABLE = "key.disable"
    KEY_ENABLE = "key.enable"  # inverse of key.disable (audit 16)
    KEY_ROTATE = "key.rotate"
    KEY_SCHEDULE_DELETION = "key.schedule_deletion"
    # --- Storage family (cloud audit, additive) -----------------------
    BUCKET_LOCKDOWN = "bucket.lockdown"
    BUCKET_UNLOCK = "bucket.unlock"  # inverse of bucket.lockdown (audit 16)
    USER_DISABLE = "user.disable"
    USER_FORCE_LOGOUT = "user.force_logout"
    USER_RESET_MFA = "user.reset_mfa"
    # --- Identity family extension (additive within ABI 1.0) ----------
    # Justification : the original three (disable / force_logout /
    # reset_mfa) miss the most common identity-IR primitives surfaced
    # by every major IAM (Okta, Azure AD, Google Workspace, AD).
    # Vendor-neutrality verified against those four catalogs before
    # admission. See docs/canon-migration/08-identity-gap-audit.md.
    USER_REVOKE_TOKENS = "user.revoke_tokens"
    USER_RESET_PASSWORD = "user.reset_password"
    USER_EXPIRE_PASSWORD = "user.expire_password"
    USER_UNLOCK = "user.unlock"
    USER_GROUP_REMOVE = "user.group_remove"
    USER_DELETE = "user.delete"
    EMAIL_QUARANTINE = "email.quarantine"
    EMAIL_RECALL = "email.recall"
    DOMAIN_BLOCK = "domain.block"
    IP_BLOCK = "ip.block"
    URL_BLOCK = "url.block"
    CERT_REVOKE = "cert.revoke"
    ALERT_ACKNOWLEDGE = "alert.acknowledge"
    CASE_UPDATE_STATUS = "case.update_status"
    PLAYBOOK_TRIGGER = "playbook.trigger"


class ResponseActionScope(StrEnum):
    """Where a response action operates."""

    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    NETWORK = "network"
    MAIL = "mail"
    PKI = "pki"
    PLATFORM = "platform"


class ResponseActionReversibility(StrEnum):
    """Whether a response action can be reversed.

    Four states distinguish operational reality, not just the
    presence of an inverse action in the catalog :

    - ``REVERSIBLE`` : a clean inverse action restores state with no
      lasting side effects (e.g. ``ip.block`` ↔ ``ip.unblock``,
      ``email.quarantine`` ↔ ``email.release``).
    - ``DISRUPTIVE`` : the action is operationally reversible
      (the vendor exposes a way to undo it), but in-flight state
      is destroyed and not recoverable (e.g. ``host.isolate`` drops
      live TCP sessions; ``host.restart`` kills in-memory state;
      ``user.disable`` loses unsaved work). The test is "does
      vendor-side reversal exist", not "does our canon already
      ship an inverse action". The system returns to a working
      state — not to the exact state before. Containment-class
      actions typically land here.
    - ``DESTRUCTIVE`` : no inverse exists. Remediation requires
      generating new state (``user.reset_password`` makes the old
      credential gone forever ; ``cert.revoke`` is permanent on the
      CRL ; ``process.kill`` orphans children and releases handles
      with no possible reversal). Eradication-class actions.
    - ``VARIES`` : depends on params or runtime context (e.g.
      ``playbook.trigger`` whose body decides the reversibility).

    Approval policy guidance : runtimes typically gate
    ``destructive`` and ``disruptive`` actions through an approval
    flow even when ``reversible`` actions auto-execute, because the
    blast radius of "reversible if you remember to undo it" is still
    operationally significant.
    """

    REVERSIBLE = "reversible"
    DISRUPTIVE = "disruptive"
    DESTRUCTIVE = "destructive"
    VARIES = "varies"


class ApprovalLevel(StrEnum):
    """Required approval level before an action executes."""

    NONE = "none"
    ANALYST = "analyst"
    SENIOR = "senior"
    MANAGER = "manager"


class ConnectorAuthModel(StrEnum):
    """Supported authentication families a connector can declare."""

    API_KEY = "api_key"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    OAUTH2_USER_DELEGATION = "oauth2_user_delegation"
    MTLS = "mtls"


class ConnectorKind(StrEnum):
    """High-level taxonomy for connectors."""

    EDR = "edr"
    SIEM = "siem"
    IAM = "iam"
    EMAIL = "email"
    NETWORK = "network"
    THREAT_INTEL = "threat_intel"
    CASE_MANAGEMENT = "case_management"
    OTHER = "other"


class IngressDelivery(StrEnum):
    """How a connector delivers events to the runtime."""

    POLLING = "polling"
    WEBHOOK = "webhook"
    STREAMING = "streaming"


class FreshnessHint(StrEnum):
    """Hint about how fresh the data an enricher returns is.

    The runtime / orchestrator uses this to decide caching policy and
    whether to re-query when an enriched artifact ages out. It is
    NOT a guarantee — vendors with stronger or weaker freshness can
    document the actual SLA in their connector's prose.
    """

    REALTIME = "realtime"  # ≤ 1 minute, queried per request
    NEAR_REALTIME = "near_realtime"  # ≤ 1 hour
    DAILY = "daily"  # cached daily refresh
    WEEKLY = "weekly"  # cached weekly refresh
    UNKNOWN = "unknown"


class DryRunScope(StrEnum):
    """What a connector's dry-run mode validates."""

    NONE = "none"
    EGRESS = "egress"
    INGRESS = "ingress"
    FULL = "full"


class FailureCategory(StrEnum):
    """Normalized failure classes — connectors map vendor errors to one of these."""

    AUTH = "auth"
    NOT_FOUND = "not_found"
    STATE_CONFLICT = "state_conflict"
    TRANSIENT = "transient"
    POLICY = "policy"


class ExecutionPhase(StrEnum):
    """Stage of the action lifecycle producing this audit row."""

    DRY_RUN = "dry_run"
    APPROVAL = "approval"
    APPLY = "apply"
    VERIFY = "verify"
    CLEANUP = "cleanup"


class ExecutionOutcome(StrEnum):
    """Outcome of an action execution stage.

    ``PENDING_APPROVAL`` is **non-terminal**: the action is paused
    awaiting an out-of-band human decision. Runtimes MUST NOT cache
    a pending result; the caller is expected to re-invoke after
    approval. All other values are terminal.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    EXPIRED = "expired"
    PENDING_APPROVAL = "pending_approval"


class SelectorRepresentation(StrEnum):
    """How :class:`ResponseSubject.selector_value` is encoded.

    Lets the audit chain stay append-only without violating the GDPR
    right-to-erasure for PII identifiers (user emails, UPNs, ...).
    The actual identifier is hashed at the producer side ; the audit
    row carries the hash + a key reference so a tenant-side rotatable
    salt lookup can still resolve it within a defined retention window.

    - ``RAW`` : ``selector_value`` is the identifier verbatim. Safe
      for non-PII selectors (agent_ids, host UUIDs, bucket names).
    - ``SHA256`` : ``selector_value`` is the lowercase-hex sha256
      digest of the identifier. Reversible only via brute force
      over the input space. ``selector_key_id`` MUST identify the
      hash domain (e.g. ``tenant:T-001:domain:user_principal_name``)
      so consumers don't accidentally compare hashes from different
      domains.
    - ``SHA256_SALTED`` : ``selector_value`` is the lowercase-hex
      sha256 digest of ``salt || identifier``. The salt is stored
      tenant-side in a rotatable secret store ; rotating the salt
      makes pre-rotation hashes effectively non-reversible (de-facto
      erasure). ``selector_key_id`` identifies the salt + version
      (e.g. ``tenant:T-001:salt:v3``).

    Doctrine : actions in families ``identity`` / ``email`` / ``iam``
    MUST use ``SHA256_SALTED`` when the upstream identifier carries
    PII. The runtime enforces this gate before any audit row is
    signed — see ``AbiRunner`` PII enforcement.
    """

    RAW = "raw"
    SHA256 = "sha256"
    SHA256_SALTED = "sha256_salted"


class ComplianceScope(StrEnum):
    """Regulated perimeter an action may touch.

    Tags on :class:`AuditRow` so audit queries can answer "everything
    that touched the PCI cardholder-data environment last quarter".
    Empty list means the action is outside any tagged regulated
    perimeter. Multiple tags are valid (a payment processor's IAM
    rotation can be in scope of both PCI DSS v4 and DORA at once).
    """

    NIS2 = "nis2"
    DORA = "dora"
    PCI_DSS_V4 = "pci_dss_v4"
    SOX = "sox"
    HDS = "hds"
    SECNUMCLOUD = "secnumcloud"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"


# =============================================================================
# ConnectorCapability — the manifest a connector publishes about itself
# =============================================================================


class AuthDescriptor(SpecModel):
    """How a connector authenticates against its upstream vendor API."""

    model: ConnectorAuthModel
    scopes: list[str] = Field(default_factory=list)
    discovery_url: str | None = None


class IngressDescriptor(SpecModel):
    """What the connector pulls/receives FROM the upstream vendor."""

    produces: list[str] = Field(default_factory=list)
    delivery: IngressDelivery = IngressDelivery.POLLING
    polling_min_interval_s: int | None = Field(default=None, ge=1)


class EgressDescriptor(SpecModel):
    """What response actions this connector can execute on the upstream vendor."""

    supports_response_actions: list[ResponseActionId] = Field(default_factory=list)


class EnrichmentDescriptor(SpecModel):
    """What canonical artifacts this connector can PRODUCE on what subjects.

    Read-side analogue of :class:`EgressDescriptor`. Where egress
    declares verbs (which response actions the connector implements),
    enrichment declares **shapes** : which canonical artifact types
    the connector produces (the ``artifact_type`` strings that ride
    in :class:`~warlog_spec.artifacts.ArtifactEnvelope`), on which
    entity / IOC kinds it can be invoked, with what freshness, and
    whether it supports bulk lookups.

    A connector with empty enrichment (default) declares "I don't do
    read-side enrichment" — the runtime won't route enrichment
    requests to it. A connector with non-empty enrichment is
    expected to implement :class:`~warlog_spec.abi.AbiEnricher`
    and return :class:`~warlog_spec.artifacts.EnrichmentAssessment`
    (or another envelope-bearing canonical shape).

    The ``produces_artifact_types`` vocabulary is intentionally open
    (free-form strings) at this stage of the spec ; common values
    today are ``"enrichment.context"``, ``"ioc.reputation"``,
    ``"mitre.assessment"``. A registry / enum can land later if a
    canonical set crystallizes.
    """

    produces_artifact_types: list[str] = Field(default_factory=list)
    supports_entity_types: list[str] = Field(
        default_factory=list,
        description=(
            "EntityType values the enricher can resolve. Open list to keep the "
            "spec resilient against EntityType growth ; concrete enricher implementations "
            "MUST match values to the canonical EntityType enum at runtime."
        ),
    )
    supports_ioc_types: list[str] = Field(
        default_factory=list,
        description="IOCType values the enricher can resolve.",
    )
    freshness: FreshnessHint = FreshnessHint.UNKNOWN
    bulk_lookup: bool = Field(
        default=False,
        description=(
            "True when the enricher can accept N subjects in a single call "
            "and amortize the per-call cost. The runtime SHOULD batch "
            "subjects into bulk calls when this is True."
        ),
    )


class DryRunDescriptor(SpecModel):
    """Dry-run capability description."""

    supported: bool = False
    scope: DryRunScope = DryRunScope.NONE


class LifecycleDescriptor(SpecModel):
    """Connector lifecycle features the runtime can rely on."""

    supports_health_check: bool = False
    supports_credential_rotation: bool = False
    supports_paused_state: bool = False


class ConnectorCompat(SpecModel):
    """Spec compatibility range the connector claims to support."""

    warlog_spec_min: str
    warlog_spec_max: str


class ConnectorCapability(SpecModel):
    """Declarative manifest a connector publishes about itself.

    A connector can be write-only (``egress`` populated, ``enrichment``
    empty), read-only (``enrichment`` populated, ``egress`` empty), or
    bi-directional (both populated). The runtime routes requests
    based on the populated descriptors.
    """

    spec_version: Literal["1.0"] = ABI_VERSION
    connector_id: str = Field(min_length=1, max_length=64)
    connector_version: str
    vendor: str
    kind: ConnectorKind
    auth: AuthDescriptor
    ingress: IngressDescriptor = Field(default_factory=IngressDescriptor)
    egress: EgressDescriptor = Field(default_factory=EgressDescriptor)
    enrichment: EnrichmentDescriptor = Field(default_factory=EnrichmentDescriptor)
    dry_run: DryRunDescriptor = Field(default_factory=DryRunDescriptor)
    lifecycle: LifecycleDescriptor = Field(default_factory=LifecycleDescriptor)
    compat: ConnectorCompat


# =============================================================================
# ResponseAction — request, result, and subject shape
# =============================================================================


class ResponseSubject(SpecModel):
    """Identifies the target of a response action.

    ``selector_representation`` indicates whether ``selector_value`` is
    the raw identifier or a hashed/pseudonymized form. When the value
    is pseudonymized (``sha256`` or ``sha256_salted``), ``selector_key_id``
    is REQUIRED so consumers can resolve the hash domain or rotation
    epoch. Doctrine : actions in PII-bearing families (identity, email,
    iam) MUST use ``sha256_salted`` — the runtime enforces this gate.
    """

    model_config = {
        "json_schema_extra": {
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "selectorRepresentation": {
                                "enum": ["sha256", "sha256_salted"]
                            }
                        },
                        "required": ["selectorRepresentation"],
                    },
                    "then": {
                        "properties": {
                            "selectorValue": {"pattern": HEX64_PATTERN},
                            "selectorKeyId": {"type": "string", "minLength": 1},
                        },
                        "required": ["selectorKeyId"],
                    },
                }
            ]
        }
    }

    kind: ResponseActionScope
    selector_type: str
    selector_value: str
    selector_representation: SelectorRepresentation = SelectorRepresentation.RAW
    selector_key_id: str | None = Field(
        default=None,
        description=(
            "Identifier of the hash domain or rotatable salt. REQUIRED when "
            "selector_representation is sha256 or sha256_salted. Format is "
            "operator-defined; common pattern is 'tenant:<id>:salt:v<N>'."
        ),
    )

    @model_validator(mode="after")
    def _enforce_pseudonymized_shape(self) -> "ResponseSubject":
        if self.selector_representation is SelectorRepresentation.RAW:
            return self
        if not self.selector_key_id:
            raise ValueError(
                f"selector_representation={self.selector_representation.value!r} "
                "requires a non-empty selector_key_id (hash domain / salt rotation epoch)"
            )
        if not _is_hex64(self.selector_value):
            raise ValueError(
                f"selector_representation={self.selector_representation.value!r} "
                "requires selector_value to be lowercase hex sha256 (64 chars)"
            )
        return self


class ApprovalDescriptor(SpecModel):
    """Approval gate metadata for a response action request."""

    required: bool = True
    level: ApprovalLevel = ApprovalLevel.ANALYST
    rationale: str


class ResponseActionSpec(SpecModel):
    """A request to execute a response action."""

    spec_version: Literal["1.0"] = ABI_VERSION
    action_id: ResponseActionId
    subject: ResponseSubject
    params: dict[str, object] = Field(default_factory=dict)
    approval: ApprovalDescriptor = Field(
        default_factory=lambda: ApprovalDescriptor(rationale="")
    )
    dry_run: bool = False
    idempotency_key: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class ConnectorError(SpecModel):
    """Normalized error returned by a connector.

    Vendor-specific codes are preserved in ``vendor_*`` fields — the
    category is additive, never lossy.
    """

    spec_version: Literal["1.0"] = ABI_VERSION
    category: FailureCategory
    message: str
    retryable: bool
    vendor_code: str | None = None
    vendor_message: str | None = None


class ResponseActionResult(SpecModel):
    """Outcome reported by the connector after an action attempt."""

    model_config = {
        "json_schema_extra": {
            "allOf": [
                {
                    "if": {"properties": {"outcome": {"const": "failure"}}},
                    "then": {
                        "properties": {"error": {"not": {"type": "null"}}},
                        "required": ["error"],
                    },
                },
                {
                    "if": {"properties": {"outcome": {"const": "success"}}},
                    "then": {"properties": {"error": {"type": "null"}}},
                },
            ]
        }
    }

    spec_version: Literal["1.0"] = ABI_VERSION
    execution_id: str
    action_id: ResponseActionId
    outcome: ExecutionOutcome
    subject: ResponseSubject
    details: dict[str, object] = Field(default_factory=dict)
    error: ConnectorError | None = None

    @model_validator(mode="after")
    def _enforce_error_matches_outcome(self) -> "ResponseActionResult":
        if self.outcome is ExecutionOutcome.FAILURE and self.error is None:
            raise ValueError("outcome='failure' requires error")
        if self.outcome is ExecutionOutcome.SUCCESS and self.error is not None:
            raise ValueError("outcome='success' must not include error")
        return self


# =============================================================================
# Decision / signal / agent references — the v2 trust-layer additions
# =============================================================================


class AgentCompositionKind(StrEnum):
    """Soft taxonomy of agent composition patterns.

    Set on :class:`AiAgentRef.composition_kind` to tag the
    architectural pattern this agent fits. Open via additive RFCs
    when new patterns crystallize.
    """

    SINGLE = "single"
    ORCHESTRATOR = "orchestrator"
    DELEGATED = "delegated"
    TOOL_USING = "tool_using"
    RETRIEVAL_AUGMENTED = "retrieval_augmented"
    COMPOSITE = "composite"


class AiAgentRef(SpecModel):
    """Identity of an automated agent that initiated an action.

    Required when :class:`AutomationActor` is the actor. The shape is
    designed for EU AI Act traceability : an auditor can recompute
    why an agent chose this action from the model identity, the
    pinned system prompt, and the run-scoped reasoning artifact.

    ``system_prompt_hash`` is sha256 of the canonical system prompt
    bytes — chains the agent's policy to the action. ``agent_run_id``
    groups all actions emitted in one ReAct loop / one autonomous
    decision-cycle. ``reasoning_artifact_ref`` optionally points at a
    persisted CoT / tool-call trace (the operator decides where it
    lives ; the ref is opaque).

    RFC-0002 additive fields (all optional) extend attribution to
    multi-agent compositions, tool-using agents, and RAG-grounded
    agents :

    - ``sub_agents`` — when an orchestrator delegated to peers /
      children, the chain of sub-agents that participated. Recursive.
    - ``tools_manifest_hash`` — sha256 of the canonical-bytes
      serialization of the tool / MCP-server manifest available at
      decision time. Lets an auditor confirm no out-of-band tool was
      injected.
    - ``retrieval_context_ref`` — opaque ref to the RAG context the
      agent had at decision time (vector-store query id, document
      set hash, …).
    - ``composition_kind`` — soft taxonomy tag, defaults to ``SINGLE``
      / absent for backward compatibility.
    """

    model: str = Field(min_length=1, description="Model identifier (e.g. 'gpt-4o', 'claude-opus-4-7')")
    model_version: str = Field(min_length=1, description="Pinned model version or build")
    system_prompt_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=HEX64_PATTERN,
        description="sha256 of the canonical system prompt bytes (64 hex chars)",
    )
    agent_run_id: str = Field(min_length=1, description="UUID grouping all actions for one agent decision-cycle")
    reasoning_artifact_ref: str | None = Field(
        default=None,
        description=(
            "Opaque reference to the persisted reasoning artifact (CoT, tool-call trace). "
            "Operator-defined storage. Optional but strongly recommended for AI Act compliance."
        ),
    )
    # RFC-0002 extensions — additive, backward-compatible.
    sub_agents: list["AiAgentRef"] = Field(
        default_factory=list,
        description=(
            "Chain of sub-agents that participated in the decision. "
            "Recursive. Empty / absent means single-agent attribution."
        ),
    )
    tools_manifest_hash: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        pattern=HEX64_PATTERN,
        description=(
            "sha256 of the canonical-bytes serialization of the tool / MCP-server "
            "manifest available at decision time. Lets an auditor confirm the "
            "agent's tool surface was the expected one."
        ),
    )
    retrieval_context_ref: str | None = Field(
        default=None,
        description=(
            "Opaque reference to the retrieval context (RAG snapshot, vector-store "
            "query id, document set hash) the agent had at decision time."
        ),
    )
    composition_kind: AgentCompositionKind | None = Field(
        default=None,
        description=(
            "Soft taxonomy tag for the agent's composition pattern. None / absent "
            "means single-agent (legacy v1 attribution)."
        ),
    )


class HumanActor(SpecModel):
    """A human operator initiated this action."""

    kind: Literal["human"] = "human"
    id: str = Field(min_length=1, description="User identifier (SSO sub, email, UPN)")


class AutomationActor(SpecModel):
    """An automated agent initiated this action.

    ``agent`` is REQUIRED — an automation row without an
    :class:`AiAgentRef` cannot prove which model authorized the
    action. This is the EU AI Act traceability anchor.
    """

    kind: Literal["automation"] = "automation"
    id: str = Field(min_length=1, description="Automation identifier (playbook id, agent name)")
    agent: AiAgentRef


AuditActor = Annotated[
    Union[HumanActor, AutomationActor],
    Field(discriminator="kind"),
]
"""Discriminated union — ``kind=human`` → :class:`HumanActor`, ``kind=automation`` → :class:`AutomationActor`."""


class DecisionArtifactType(StrEnum):
    """Catalog of artifact types that can motivate an action.

    Used by :class:`DecisionRef` to type-tag the upstream artifact.
    Open for extension via MINOR bumps; consumers MUST tolerate
    values they don't recognize and surface them as opaque refs.
    """

    TRIAGE_PROPOSAL = "triage_proposal"
    NEXT_STEP_PROPOSAL = "next_step_proposal"
    PLAYBOOK_CANDIDATE_PROPOSAL = "playbook_candidate_proposal"
    INVESTIGATION_SUMMARY_PROPOSAL = "investigation_summary_proposal"
    CLASSIFICATION_ASSESSMENT = "classification_assessment"
    MITRE_ASSESSMENT = "mitre_assessment"
    ENRICHMENT_ASSESSMENT = "enrichment_assessment"
    CLOSURE_SUMMARY = "closure_summary"
    CASE_RETURN_SUMMARY = "case_return_summary"
    RISK_ARBITRATION = "risk_arbitration"
    APPROVAL_DECISION = "approval_decision"


class DecisionRef(SpecModel):
    """Cryptographic pointer to the decision that motivated an action.

    Closes the contract hole the v1 :class:`AuditRow` had : nothing
    in the audit row linked back to the proposal / arbitration /
    approval artifact that justified the action. ``content_hash`` is
    sha256 of the canonical-bytes serialization of the referenced
    artifact — an auditor can fetch the artifact by ``artifact_id``
    and confirm it has not been mutated since the audit row was signed.
    """

    artifact_type: DecisionArtifactType
    artifact_id: str = Field(min_length=1)
    content_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=HEX64_PATTERN,
        description="sha256 of the canonical-bytes serialization of the referenced artifact",
    )


class TriggerSignalKind(StrEnum):
    """What kind of upstream signal motivated an action.

    ``manual`` is a first-class value — an analyst initiating an
    action without an upstream alert (e.g. responding to a phone
    call from a user) is a legitimate flow and the audit row MUST
    NOT pretend it had a signal.
    """

    OCSF_EVENT = "ocsf_event"
    ALERT = "alert"
    IOC = "ioc"
    PLAYBOOK_TICK = "playbook_tick"
    MANUAL = "manual"


class TriggerSignalRef(SpecModel):
    """Cryptographic pointer to the upstream signal that motivated an action.

    For ``manual``, ``source_id`` and ``content_hash`` MAY be empty
    strings (the analyst clicked without a signal). For all other
    kinds, both fields are REQUIRED and ``content_hash`` is sha256
    of the canonical-bytes serialization of the signal payload.
    """

    model_config = {
        "json_schema_extra": {
            "allOf": [
                {
                    "if": {
                        "properties": {"kind": {"not": {"const": "manual"}}},
                        "required": ["kind"],
                    },
                    "then": {
                        "properties": {
                            "sourceId": {"type": "string", "minLength": 1},
                            "contentHash": {"pattern": HEX64_PATTERN},
                        },
                        "required": ["sourceId", "contentHash"],
                    },
                }
            ]
        }
    }

    kind: TriggerSignalKind
    source_id: str = Field(
        default="",
        description="Identifier of the signal (alert UUID, OCSF event id, IOC value). Empty for manual.",
    )
    content_hash: str = Field(
        default="",
        description=(
            "sha256 (64 hex) of the canonical-bytes serialization of the signal payload. "
            "Empty string allowed only when kind=manual."
        ),
    )

    @model_validator(mode="after")
    def _enforce_signal_pointer_shape(self) -> "TriggerSignalRef":
        if self.kind is TriggerSignalKind.MANUAL:
            if self.content_hash and not _is_hex64(self.content_hash):
                raise ValueError("manual trigger content_hash must be empty or lowercase hex sha256")
            return self
        if not self.source_id:
            raise ValueError(f"trigger kind {self.kind.value!r} requires source_id")
        if not _is_hex64(self.content_hash):
            raise ValueError(f"trigger kind {self.kind.value!r} requires lowercase hex sha256 content_hash")
        return self


# =============================================================================
# AuditRow — append-only execution log (v2)
# =============================================================================


class AuditConnectorRef(SpecModel):
    """Reference to the connector that handled the execution stage."""

    id: str
    version: str


class AuditRow(SpecModel):
    """Append-only execution audit row.

    Every action lifecycle stage (``dry_run`` → ``approval`` → ``apply``
    → ``verify`` → ``cleanup``) writes one row. Rows are signed at
    write (HMAC of canonical bytes + previous-row hash) for tamper
    evidence — see :mod:`warlog_spec.audit_chain`.

    ABI v2.0 closes the four trust-layer holes the v1 row had :
    ``decision_ref`` cryptographically links the row to the decision
    artifact (TriageProposal, RiskArbitration, ApprovalDecision, …),
    ``trigger_signal_ref`` links to the upstream signal (OCSF event,
    alert, IOC), ``compliance_scope`` tags regulated perimeters
    touched (NIS2 / DORA / PCI DSS v4 / …), and the AI-agent identity
    rides inside :class:`AutomationActor` when ``actor.kind=automation``.
    """

    model_config = {
        "json_schema_extra": {
            "allOf": [
                {
                    "if": {"properties": {"outcome": {"const": "failure"}}},
                    "then": {
                        "properties": {"error": {"not": {"type": "null"}}},
                        "required": ["error"],
                    },
                },
                {
                    "if": {"properties": {"outcome": {"const": "success"}}},
                    "then": {"properties": {"error": {"type": "null"}}},
                },
            ]
        }
    }

    spec_version: Literal["1.0"] = ABI_VERSION
    audit_id: str
    execution_id: str
    tenant_id: str
    actor: AuditActor
    action_id: ResponseActionId
    subject: ResponseSubject
    phase: ExecutionPhase
    outcome: ExecutionOutcome
    started_at: datetime
    completed_at: datetime | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    error: ConnectorError | None = None
    connector: AuditConnectorRef
    idempotency_key: str
    # --- v2 trust-layer additions (REQUIRED) -------------------------------
    decision_ref: DecisionRef
    trigger_signal_ref: TriggerSignalRef
    compliance_scope: list[ComplianceScope] = Field(
        description=(
            "Regulated perimeters this action touches. REQUIRED field but MAY be empty "
            "when the action is outside any tagged regulated scope — producers must make "
            "the empty-vs-tagged decision explicitly rather than rely on a default."
        ),
    )
    # --- Approval transition pointer (optional) ----------------------------
    # Set when this row supersedes an earlier row in the same execution —
    # typically a row carrying outcome=pending_approval being resolved.
    # Lets a consumer reconstruct the (pending → approved/denied) edge
    # without correlating execution_id + ordering by hand.
    prior_audit_id: str | None = Field(
        default=None,
        description=(
            "Audit ID of the row this one supersedes in the same execution. "
            "Doctrine : populated when resolving a pending_approval row, "
            "and OPTIONAL elsewhere. Lets consumers reconstruct lifecycle edges."
        ),
    )

    @model_validator(mode="after")
    def _enforce_error_matches_outcome(self) -> "AuditRow":
        if self.outcome is ExecutionOutcome.FAILURE and self.error is None:
            raise ValueError("outcome='failure' requires error")
        if self.outcome is ExecutionOutcome.SUCCESS and self.error is not None:
            raise ValueError("outcome='success' must not include error")
        return self


# =============================================================================
# SignedAuditRow — public, transportable, verifiable envelope (Pydantic shape)
# =============================================================================


class AuditAttestation(SpecModel):
    """Cryptographic attestation enveloping an :class:`AuditRow`.

    The fields here are sufficient for a recipient with the matching
    HMAC secret to verify the row end-to-end :

    1. Re-canonicalize the embedded ``AuditRow`` using
       ``canonicalization_format`` (today only ``v1``).
    2. Compute ``HMAC(prev_row_hash || canonical_bytes, secret)``
       under ``algorithm`` (today only ``HMAC-SHA256``).
    3. Compare against ``signature_value``.

    The bytes that were actually signed are NOT carried inline (a
    consumer recomputes them from ``payload``) — this is what
    decouples on-the-wire size from chain-history depth. For the
    canonical bytes to be reproducible regardless of Pydantic schema
    drift, the format identifier (``canonicalization_format``) is
    bumped independently of ``AuditRow.spec_version`` when the
    canonicalizer itself changes.

    ``key_id`` lets the operator rotate HMAC secrets without breaking
    historical verification : old rows continue to verify under their
    original ``key_id``.
    """

    prev_row_hash: str = Field(
        min_length=64,
        max_length=64,
        pattern=HEX64_PATTERN,
        description=(
            "HMAC hex digest of the prior row in the chain, or the per-tenant "
            "genesis hash when this is the first row."
        ),
    )
    signature_value: str = Field(
        min_length=64,
        max_length=4096,
        pattern=HEX_PATTERN,
        description=(
            "Hex-encoded signature over (prev_row_hash || canonical_bytes), "
            "under ``algorithm`` and the signing material identified by "
            "``key_id``. Length depends on algorithm : 64 hex for HMAC-SHA256, "
            "128 for Ed25519, 384-1024 for RSASSA-PSS-SHA256 (RSA 3072-8192 bit)."
        ),
    )
    algorithm: Literal["HMAC-SHA256", "Ed25519", "RSASSA-PSS-SHA256"] = Field(
        default="HMAC-SHA256",
        description=(
            "Signature algorithm. ``HMAC-SHA256`` is the symmetric default "
            "(shared secret). ``Ed25519`` and ``RSASSA-PSS-SHA256`` are "
            "asymmetric schemes for scenarios where the signer's signing "
            "material MUST NOT be shareable with the verifier (MSSP customer "
            "audits, third-party regulator audits, long-term forensic "
            "preservation). See RFC-0004."
        ),
    )
    canonicalization_format: Literal["v1"] = Field(
        default="v1",
        description=(
            "Canonical-bytes format identifier. Decoupled from "
            "``AuditRow.spec_version`` so the spec can evolve without "
            "rotating the cryptographic format, and vice versa."
        ),
    )
    key_id: str = Field(
        min_length=1,
        description=(
            "Identifier of the HMAC secret used to sign. Format is "
            "operator-defined ; common pattern is "
            "``tenant:<tenant_id>:secret:v<N>`` so rotation is explicit."
        ),
    )


class SignedAuditRow(SpecModel):
    """Public, transportable, verifiable audit row.

    Wraps an :class:`AuditRow` (the signed payload) with the
    :class:`AuditAttestation` envelope. This is the **unit of export**
    the ABI publishes : a consumer receiving a ``SignedAuditRow`` can
    re-canonicalize the payload, re-compute HMAC, and validate
    integrity end-to-end without access to the source chain store.

    Internal runtime path (``app.services.connectors.audit_chain``)
    stores the canonical bytes alongside the signature for byte-stable
    historical verification. The exported ``SignedAuditRow`` does NOT
    carry those bytes inline — a consumer re-canonicalizes ``payload``
    using ``attestation.canonicalization_format``. The two paths are
    equivalent under format invariance.
    """

    spec_version: Literal["1.0"] = ABI_VERSION
    payload: AuditRow
    attestation: AuditAttestation


__all__ = [
    "ABI_VERSION",
    "AgentCompositionKind",
    "AiAgentRef",
    "ApprovalDescriptor",
    "ApprovalLevel",
    "AuditActor",
    "AuditAttestation",
    "AuditConnectorRef",
    "AuditRow",
    "AuthDescriptor",
    "AutomationActor",
    "ComplianceScope",
    "ConnectorAuthModel",
    "ConnectorCapability",
    "ConnectorCompat",
    "ConnectorError",
    "ConnectorKind",
    "DecisionArtifactType",
    "DecisionRef",
    "DryRunDescriptor",
    "DryRunScope",
    "EgressDescriptor",
    "EnrichmentDescriptor",
    "ExecutionOutcome",
    "ExecutionPhase",
    "FailureCategory",
    "FreshnessHint",
    "HumanActor",
    "IngressDelivery",
    "IngressDescriptor",
    "LifecycleDescriptor",
    "ResponseActionId",
    "ResponseActionResult",
    "ResponseActionReversibility",
    "ResponseActionScope",
    "ResponseActionSpec",
    "ResponseSubject",
    "SelectorRepresentation",
    "SignedAuditRow",
    "TriggerSignalKind",
    "TriggerSignalRef",
]
