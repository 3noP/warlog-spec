"""End-to-end demo : "The Rogue Agent" — trust-layer in ~200 SLOC of runtime.

What this proves
----------------

The Warlog spec separates the **contract** (canonical types, the
audit-chain crypto primitives, the connector ABC) from the **runtime**
that orchestrates them. The contract lives in ``warlog_spec``. The
runtime is the operator's. This file inlines a ~200-SLOC reference
runtime (``MiniAuditChain`` ~27 SLOC + ``MiniApprovalGate`` ~23 SLOC
+ ``MiniRunner`` ~150 SLOC) that is enough to demonstrate the four
trust-layer properties on a real, executable scenario :

1. **GDPR pseudonymization gate** — the runtime refuses to sign an
   action against a raw-PII selector. The connector never sees the
   request. Pseudonymization is the caller's responsibility ; the
   runtime stores no salt, which is what makes the
   right-to-erasure-by-salt-rotation work.
2. **Approval gate** — DESTRUCTIVE actions on the identity family
   short-circuit to ``PENDING_APPROVAL``. The connector is NOT
   called until a human resolves the request out-of-band.
3. **Cryptographic chaining** — every lifecycle row HMACs over
   ``prev_hash || canonical_bytes``. Mutating a single byte in any
   historical row breaks ``verify()``.
4. **Decision pointers** — when the senior denies the action, the
   resolved audit row's ``decision_ref`` points at an
   ``ApprovalDecision`` canonical artifact, and ``prior_audit_id``
   points at the pending row it supersedes. The full chain
   (signal → proposal → approval → outcome) is traversable.

Run
---

    pip install warlog-spec
    python rogue_agent_demo.py
    python rogue_agent_demo.py --fast  # no presenter pauses

Tested against ``warlog-spec`` 0.1.0.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Literal

from warlog_spec import (
    CANONICALIZATION_FORMAT_V1,
    AbiConnector,
    AiAgentRef,
    ApprovalDescriptor,
    ApprovalLevel,
    AuditChainBroken,
    AuditConnectorRef,
    AuditRow,
    AuthDescriptor,
    AutomationActor,
    ComplianceScope,
    ConnectorAuthModel,
    ConnectorCapability,
    ConnectorCompat,
    ConnectorError,
    ConnectorKind,
    DecisionArtifactType,
    DecisionRef,
    EgressDescriptor,
    ExecutionOutcome,
    ExecutionPhase,
    FailureCategory,
    ResponseActionId,
    ResponseActionResult,
    ResponseActionScope,
    ResponseActionSpec,
    ResponseSubject,
    SelectorRepresentation,
    TriggerSignalKind,
    TriggerSignalRef,
    canonicalize_v1,
    compute_genesis,
    compute_signature,
)
from warlog_spec.action_catalog import ACTION_CATALOG
from warlog_spec.artifacts import (
    ApprovalDecision,
    ApprovalDecisionPayload,
    ArtifactEnvelope,
    ArtifactProducer,
    CanonicalArtifact,
    ResponseActionRequestRef,
)

# ASCII output is the default because Windows terminals and transcripts
# can still mojibake emoji / typographic punctuation depending on code page.
# Use ``--symbols`` for richer local output on UTF-8 terminals.
USE_SYMBOLS = "--symbols" in sys.argv
FAST_MODE = "--fast" in sys.argv or "--no-pause" in sys.argv

if USE_SYMBOLS:
    stdout_reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(stdout_reconfigure):
        stdout_reconfigure(encoding="utf-8")


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------


_ASCII_REPLACEMENTS = str.maketrans(
    {
        "—": "-",
        "–": "-",
        "→": "->",
        "←": "<-",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "…": "...",
        "\u00a0": " ",
    }
)

_STEP_LABELS = {
    "ℹ️": "INFO",
    "🤖": "AGENT",
    "🔐": "AUTH",
    "🔌": "CONNECTOR",
    "📝": "AUDIT",
    "✅": "OK",
    "⏳": "PENDING",
    "🧑‍⚖️": "REVIEW",
    "📦": "ARTIFACT",
    "🧪": "TEST",
    "🎬": "CUE",
    "▶": "NEXT",
    "❌": "ERROR",
}


def _plain(text: str) -> str:
    return text.translate(_ASCII_REPLACEMENTS).encode("ascii", "ignore").decode("ascii")


def banner(title: str) -> None:
    print()
    print("=" * 78)
    print(f"  {title if USE_SYMBOLS else _plain(title)}")
    print("=" * 78)


def step(symbol: str, msg: str) -> None:
    if USE_SYMBOLS:
        print(f"  {symbol} {msg}")
        return
    label = _STEP_LABELS.get(symbol, "STEP")
    print(f"  [{label:<9}] {_plain(msg)}")


def presenter_pause(next_title: str, note: str) -> None:
    if FAST_MODE:
        return
    print()
    print("-" * 78)
    step("🎬", f"Presenter cue: {next_title}")
    step("ℹ️", note)
    prompt = "  ▶ Press Enter when you are ready... " if USE_SYMBOLS else "  [NEXT     ] Press Enter when ready... "
    try:
        input(prompt)
    except EOFError:
        print()
    print("-" * 78)


def hexshort(h: str) -> str:
    return f"{h[:8]}..{h[-4:]}"


def hash_artifact(artifact: CanonicalArtifact) -> str:
    """Stable sha256 over the canonical JSON of any CanonicalArtifact."""
    payload = json.dumps(
        artifact.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# MiniAuditChain — reference HMAC chain (~30 lines)
# ---------------------------------------------------------------------------


@dataclass
class SignedRow:
    row: AuditRow
    prev_hash: str
    signature: str
    canonical_bytes: bytes
    canonicalization_format: str = CANONICALIZATION_FORMAT_V1


class MiniAuditChain:
    """Per-tenant HMAC-chained, append-only audit log. In-memory."""

    def __init__(self, tenant_id: str, secret: bytes) -> None:
        self._tenant_id = tenant_id
        self._secret = secret
        self._rows: list[SignedRow] = []

    def head(self) -> str:
        if not self._rows:
            return compute_genesis(self._tenant_id, self._secret)
        return self._rows[-1].signature

    def append(self, row: AuditRow) -> SignedRow:
        prev = self.head()
        canonical = canonicalize_v1(row)
        signature = compute_signature(prev, canonical, self._secret)
        signed = SignedRow(row=row, prev_hash=prev, signature=signature, canonical_bytes=canonical)
        self._rows.append(signed)
        return signed

    def verify(self) -> None:
        expected_prev = compute_genesis(self._tenant_id, self._secret)
        for s in self._rows:
            if s.prev_hash != expected_prev:
                raise AuditChainBroken(f"prev_hash mismatch at audit_id={s.row.audit_id}")
            recomputed = compute_signature(s.prev_hash, s.canonical_bytes, self._secret)
            if recomputed != s.signature:
                raise AuditChainBroken(f"signature mismatch at audit_id={s.row.audit_id}")
            expected_prev = s.signature

    def rows(self) -> list[SignedRow]:
        return list(self._rows)

    def tamper_canonical_byte(self, index: int) -> None:
        target = self._rows[index]
        self._rows[index] = SignedRow(
            row=target.row,
            prev_hash=target.prev_hash,
            signature=target.signature,
            canonical_bytes=target.canonical_bytes[:-1] + bytes([target.canonical_bytes[-1] ^ 0x01]),
            canonicalization_format=target.canonicalization_format,
        )


# ---------------------------------------------------------------------------
# MiniApprovalGate — pending / resolved bookkeeping (~20 lines)
# ---------------------------------------------------------------------------


GateState = Literal["approved", "denied", "pending"]


@dataclass
class GateDecision:
    state: GateState
    rationale: str
    request_id: str | None = None


class MiniApprovalGate:
    """Toy gate. First request → pending. Subsequent calls → resolved state if set."""

    def __init__(self) -> None:
        self._pending: dict[str, str] = {}
        self._resolutions: dict[str, GateDecision] = {}

    def request(self, spec: ResponseActionSpec) -> GateDecision:
        key = spec.idempotency_key
        if key in self._pending:
            req_id = self._pending[key]
            return self._resolutions.get(
                req_id,
                GateDecision(state="pending", rationale="awaiting decision", request_id=req_id),
            )
        req_id = f"appr-{uuid.uuid4()}"
        self._pending[key] = req_id
        return GateDecision(
            state="pending",
            rationale="senior approval required (DESTRUCTIVE identity action)",
            request_id=req_id,
        )

    def resolve(self, idempotency_key: str, *, decision: GateState, rationale: str) -> str:
        req_id = self._pending[idempotency_key]
        self._resolutions[req_id] = GateDecision(state=decision, rationale=rationale, request_id=req_id)
        return req_id


# ---------------------------------------------------------------------------
# DemoIdentityConnector — synthetic Okta-style write-side connector
# ---------------------------------------------------------------------------


class DemoIdentityConnector(AbiConnector):
    """Synthetic identity connector. Real Okta version lives at examples/okta_user_response_connector.py."""

    capability: ClassVar[ConnectorCapability] = ConnectorCapability(
        connector_id="demo.identity",
        connector_version="0.1.0",
        vendor="demo",
        kind=ConnectorKind.IAM,
        auth=AuthDescriptor(model=ConnectorAuthModel.API_KEY),
        egress=EgressDescriptor(supports_response_actions=[ResponseActionId.USER_REVOKE_TOKENS]),
        compat=ConnectorCompat(warlog_spec_min="1.0", warlog_spec_max="1.0"),
    )

    async def authenticate(self) -> None:
        step("🔐", "[demo.identity] authenticate OK (synthetic — no vendor call)")

    async def dry_run(self, spec: ResponseActionSpec) -> None:
        step("🔌", f"[demo.identity] dry_run OK for {spec.action_id.value} on {hexshort(spec.subject.selector_value)}")

    async def apply(self, spec: ResponseActionSpec) -> ResponseActionResult:
        step("🔌", f"[demo.identity] apply: revoking tokens for {hexshort(spec.subject.selector_value)}")
        return ResponseActionResult(
            execution_id="",
            action_id=spec.action_id,
            outcome=ExecutionOutcome.SUCCESS,
            subject=spec.subject,
            details={"vendor": "demo-okta", "revoked_count": 1},
        )

    async def verify(self, spec: ResponseActionSpec, result: ResponseActionResult) -> bool:
        return True


# ---------------------------------------------------------------------------
# MiniRunner — ~80 lines of reference runtime
# ---------------------------------------------------------------------------


@dataclass
class ExecutionContext:
    actor: AutomationActor
    decision_ref: DecisionRef
    trigger_signal_ref: TriggerSignalRef
    compliance_scope: list[ComplianceScope]


_PII_FAMILIES = frozenset({"identity", "email", "iam"})


class MiniRunner:
    """Orchestrates one ABI execution. dry_run → GDPR gate → approval → apply → verify."""

    def __init__(
        self,
        *,
        tenant_id: str,
        chain: MiniAuditChain,
        gate: MiniApprovalGate,
        connector: AbiConnector,
    ) -> None:
        self._tenant_id = tenant_id
        self._chain = chain
        self._gate = gate
        self._connector = connector

    async def execute(
        self,
        *,
        spec: ResponseActionSpec,
        context: ExecutionContext,
        prior_audit_id: str | None = None,
    ) -> ResponseActionResult:
        execution_id = str(uuid.uuid4())
        connector_ref = AuditConnectorRef(
            id=self._connector.capability.connector_id,
            version=self._connector.capability.connector_version,
        )

        await self._connector.authenticate()

        # 1. GDPR pseudonymization gate — runs BEFORE the connector sees anything.
        pii_err = self._gdpr_gate(spec)
        if pii_err is not None:
            signed = self._emit(
                execution_id, context, spec, connector_ref,
                ExecutionPhase.DRY_RUN, ExecutionOutcome.FAILURE, pii_err, prior_audit_id,
            )
            self._announce(signed)
            return ResponseActionResult(
                execution_id=execution_id,
                action_id=spec.action_id,
                outcome=ExecutionOutcome.FAILURE,
                subject=spec.subject,
                error=pii_err,
            )

        # 2. dry_run. prior_audit_id stays None — this row doesn't supersede anything.
        await self._connector.dry_run(spec)
        self._announce(
            self._emit(execution_id, context, spec, connector_ref,
                       ExecutionPhase.DRY_RUN, ExecutionOutcome.SUCCESS, None, None)
        )

        # 3. Approval gate. prior_audit_id is set ONLY on the resolving row
        # (non-pending outcome), per the spec doctrine on AuditRow.prior_audit_id.
        if spec.approval.required:
            decision = self._gate.request(spec)
            outcome_map = {
                "approved": ExecutionOutcome.SUCCESS,
                "denied": ExecutionOutcome.DENIED,
                "pending": ExecutionOutcome.PENDING_APPROVAL,
            }
            approval_prior = prior_audit_id if decision.state != "pending" else None
            self._announce(
                self._emit(execution_id, context, spec, connector_ref,
                           ExecutionPhase.APPROVAL, outcome_map[decision.state], None, approval_prior)
            )
            if decision.state == "pending":
                return ResponseActionResult(
                    execution_id=execution_id,
                    action_id=spec.action_id,
                    outcome=ExecutionOutcome.PENDING_APPROVAL,
                    subject=spec.subject,
                    details={"approval_request_id": decision.request_id or ""},
                )
            if decision.state == "denied":
                return ResponseActionResult(
                    execution_id=execution_id,
                    action_id=spec.action_id,
                    outcome=ExecutionOutcome.DENIED,
                    subject=spec.subject,
                    details={"rationale": decision.rationale},
                )

        # 4. Apply. prior_audit_id stays None — only the row that resolved the
        # pending state (the approval row above) supersedes the prior pending row.
        result = await self._connector.apply(spec)
        result = result.model_copy(update={"execution_id": execution_id})
        self._announce(
            self._emit(execution_id, context, spec, connector_ref,
                       ExecutionPhase.APPLY, result.outcome, result.error, None)
        )
        if result.outcome != ExecutionOutcome.SUCCESS:
            return result

        # 5. Verify.
        verified = await self._connector.verify(spec, result)
        v_outcome = ExecutionOutcome.SUCCESS if verified else ExecutionOutcome.FAILURE
        self._announce(
            self._emit(execution_id, context, spec, connector_ref,
                       ExecutionPhase.VERIFY, v_outcome, None, None)
        )
        return result

    def _gdpr_gate(self, spec: ResponseActionSpec) -> ConnectorError | None:
        meta = ACTION_CATALOG.get(spec.action_id)
        if meta is None or meta.family not in _PII_FAMILIES:
            return None
        if spec.subject.selector_representation is SelectorRepresentation.SHA256_SALTED:
            return None
        return ConnectorError(
            category=FailureCategory.POLICY,
            message=(
                f"Action {spec.action_id.value!r} targets PII family {meta.family!r}; "
                f"selector_representation MUST be 'sha256_salted' "
                f"(got: {spec.subject.selector_representation.value!r}). "
                "Pseudonymize with a rotatable tenant salt before submitting."
            ),
            retryable=False,
            vendor_code="warlog.gdpr.pii_required",
        )

    def _emit(
        self,
        execution_id: str,
        context: ExecutionContext,
        spec: ResponseActionSpec,
        connector_ref: AuditConnectorRef,
        phase: ExecutionPhase,
        outcome: ExecutionOutcome,
        error: ConnectorError | None,
        prior_audit_id: str | None,
    ) -> SignedRow:
        now = datetime.now(UTC)
        row = AuditRow(
            audit_id=str(uuid.uuid4()),
            execution_id=execution_id,
            tenant_id=self._tenant_id,
            actor=context.actor,
            action_id=spec.action_id,
            subject=spec.subject,
            phase=phase,
            outcome=outcome,
            started_at=now,
            completed_at=now,
            duration_ms=0,
            error=error,
            connector=connector_ref,
            idempotency_key=spec.idempotency_key,
            decision_ref=context.decision_ref,
            trigger_signal_ref=context.trigger_signal_ref,
            compliance_scope=list(context.compliance_scope),
            prior_audit_id=prior_audit_id,
        )
        return self._chain.append(row)

    def _announce(self, s: SignedRow) -> None:
        n = len(self._chain.rows())
        prior = f"  prior={s.row.prior_audit_id[:8]}.." if s.row.prior_audit_id else ""
        step(
            "📝",
            f"AuditRow #{n}  phase={s.row.phase.value:<8} "
            f"outcome={s.row.outcome.value:<16} "
            f"prev={hexshort(s.prev_hash)}  sig={hexshort(s.signature)}{prior}",
        )


# ---------------------------------------------------------------------------
# Scenario — "The Rogue Agent"
# ---------------------------------------------------------------------------


async def main() -> None:
    TENANT_ID = "tenant-acme-eu"
    # Demo-only secret. In production the HMAC secret lives in an HSM,
    # KMS, or sealed-secret store — NEVER in the runtime process image.
    # The runtime borrows it for the duration of a signing operation and
    # never persists it. Rotation invalidates pre-rotation chains by
    # design ; this is the operator's escape valve.
    SECRET = b"tenant-side-rotatable-audit-chain-hmac-secret-v3"
    # Per-tenant pseudonymization salt. Same custody doctrine as SECRET.
    # Rotation = de-facto erasure of pre-rotation hashes (right-to-erasure).
    SALT = b"acme-eu:user_principal_name:salt:v3"
    TARGET_EMAIL = "alice@acme.example"

    chain = MiniAuditChain(tenant_id=TENANT_ID, secret=SECRET)
    gate = MiniApprovalGate()
    connector = DemoIdentityConnector(config={})
    runner = MiniRunner(tenant_id=TENANT_ID, chain=chain, gate=gate, connector=connector)

    banner("LOCAL HARNESS — safe execution-boundary demo")
    step("ℹ️", "This is not a production Okta integration.")
    step("ℹ️", "It uses a synthetic identity connector so no external system is touched.")
    step("ℹ️", "The enforcement path, approval gate, and HMAC audit artifacts are real.")
    step("ℹ️", "Goal: show the boundary before an AI agent can trigger a destructive action.")
    presenter_pause(
        "Act I - raw PII refusal",
        "The agent will try a destructive identity action with a cleartext email selector.",
    )

    # --- AI agent identity (EU AI Act traceability anchor) ----------------
    SYSTEM_PROMPT = b"You are a fraud-triage agent. Investigate VPN anomalies, propose containment."
    TOOLS_MANIFEST = b'{"tools":["okta.revoke_tokens","okta.list_sessions"]}'
    agent = AiAgentRef(
        model="gpt-4o",
        model_version="2026-04-01",
        system_prompt_hash=hashlib.sha256(SYSTEM_PROMPT).hexdigest(),
        agent_run_id=str(uuid.uuid4()),
        reasoning_artifact_ref="kvstore://reasoning/run-001",
        tools_manifest_hash=hashlib.sha256(TOOLS_MANIFEST).hexdigest(),
    )
    actor = AutomationActor(id="playbook.fraud_triage", agent=agent)

    # --- Upstream signal that triggered the agent --------------------------
    alert_bytes = b'{"alert_id":"alert-2026-05-20-7f3e","severity":"high","reason":"concurrent_geo_login"}'
    trigger_signal_ref = TriggerSignalRef(
        kind=TriggerSignalKind.ALERT,
        source_id="alert-2026-05-20-7f3e",
        content_hash=hashlib.sha256(alert_bytes).hexdigest(),
    )

    # --- Agent-produced NextStepProposal that motivates the action ---------
    proposal_bytes = b'{"proposed_action":"user.revoke_tokens","rationale":"VPN anomaly + concurrent geo logins"}'
    proposal_ref = DecisionRef(
        artifact_type=DecisionArtifactType.NEXT_STEP_PROPOSAL,
        artifact_id=f"prop-{uuid.uuid4()}",
        content_hash=hashlib.sha256(proposal_bytes).hexdigest(),
    )

    context_initial = ExecutionContext(
        actor=actor,
        decision_ref=proposal_ref,
        trigger_signal_ref=trigger_signal_ref,
        compliance_scope=[ComplianceScope.GDPR, ComplianceScope.NIS2],
    )

    # ======================================================================
    # ACT I — Rogue Agent submits a RAW PII selector → GDPR gate rejects
    # ======================================================================
    banner("ACT I — Rogue Agent submits a raw PII selector")
    step("🤖", f"Agent run {agent.agent_run_id[:8]}.. proposes user.revoke_tokens on '{TARGET_EMAIL}'")
    step("🤖", "Selector representation: RAW (cleartext email). Submitting to runtime...")

    spec_naive = ResponseActionSpec(
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject=ResponseSubject(
            kind=ResponseActionScope.IDENTITY,
            selector_type="user_principal_name",
            selector_value=TARGET_EMAIL,
        ),
        params={"reason": "VPN anomaly + concurrent geo logins"},
        approval=ApprovalDescriptor(
            required=True,
            level=ApprovalLevel.SENIOR,
            rationale="DESTRUCTIVE identity action; EU AI Act traceability required.",
        ),
        idempotency_key=f"act1-{uuid.uuid4()}",
    )
    result_act1 = await runner.execute(spec=spec_naive, context=context_initial)

    assert result_act1.outcome == ExecutionOutcome.FAILURE
    assert result_act1.error is not None
    assert result_act1.error.vendor_code == "warlog.gdpr.pii_required"
    step("✅", f"Runtime refused. vendor_code={result_act1.error.vendor_code}")
    step("ℹ️", "Doctrine: the runtime stores NO salt. Pseudonymization is the caller's job.")
    step("ℹ️", "             Salt rotation = de-facto erasure without mutating the chain.")
    presenter_pause(
        "Act II - approval boundary",
        "The agent retries with a pseudonymized selector, but the action is still destructive.",
    )

    # ======================================================================
    # ACT II — Compliant resubmission → PENDING_APPROVAL (connector NOT called)
    # ======================================================================
    banner("ACT II — Agent retries with sha256_salted selector")
    pseudonymized = hashlib.sha256(SALT + TARGET_EMAIL.encode("utf-8")).hexdigest()
    step("🤖", f"Agent re-hashes target: sha256(salt || email) = {hexshort(pseudonymized)}")
    step("🤖", "Action is DESTRUCTIVE per catalogue → SENIOR approval expected.")

    shared_idempotency_key = f"act23-{uuid.uuid4()}"
    spec_compliant = ResponseActionSpec(
        action_id=ResponseActionId.USER_REVOKE_TOKENS,
        subject=ResponseSubject(
            kind=ResponseActionScope.IDENTITY,
            selector_type="user_principal_name",
            selector_value=pseudonymized,
            selector_representation=SelectorRepresentation.SHA256_SALTED,
            selector_key_id="tenant:acme-eu:salt:v3",
        ),
        params={"reason": "VPN anomaly + concurrent geo logins"},
        approval=ApprovalDescriptor(
            required=True,
            level=ApprovalLevel.SENIOR,
            rationale="DESTRUCTIVE identity action; EU AI Act traceability required.",
        ),
        idempotency_key=shared_idempotency_key,
    )
    result_act2 = await runner.execute(spec=spec_compliant, context=context_initial)
    assert result_act2.outcome == ExecutionOutcome.PENDING_APPROVAL
    pending_audit_id = chain.rows()[-1].row.audit_id
    pending_request_id = result_act2.details["approval_request_id"]
    step("⏳", f"Runtime paused. approval_request_id={str(pending_request_id)[:13]}..")
    step("ℹ️", "             The connector apply() was NEVER called. No vendor side-effect possible.")
    presenter_pause(
        "Act III - human denial",
        "The senior operator resolves the pending request out-of-band instead of letting the agent execute.",
    )

    # ======================================================================
    # ACT III — Senior denies → ApprovalDecision artifact → DENIED row
    # ======================================================================
    banner("ACT III — Senior operator denies the action out-of-band")
    step("🧑‍⚖️", "Senior operator reviews decision trace + alert evidence and DENIES.")

    gate.resolve(
        idempotency_key=shared_idempotency_key,
        decision="denied",
        rationale="Agent reasoning under-supported. Block-and-wait, do NOT revoke tokens.",
    )

    # Build the canonical ApprovalDecision artifact for traceability.
    decision_artifact = ApprovalDecision(
        envelope=ArtifactEnvelope(
            artifact_type="approval_decision",
            subject_type="alert",
            subject_id=trigger_signal_ref.source_id,
            producer=ArtifactProducer(kind="human", name="senior.ops@acme-eu"),
            generated_at=datetime.now(UTC),
        ),
        payload=ApprovalDecisionPayload(
            request_ref=ResponseActionRequestRef(
                action_id=spec_compliant.action_id.value,
                subject_kind=spec_compliant.subject.kind.value,
                subject_value=spec_compliant.subject.selector_value,
                idempotency_key=shared_idempotency_key,
            ),
            decision_maker_kind="human",
            decision_maker_id="senior.ops@acme-eu",
            decision="denied",
            decided_at=datetime.now(UTC),
            rationale="Agent reasoning under-supported. Block-and-wait, do NOT revoke tokens.",
        ),
    )
    decision_artifact_id = f"appr-decision-{uuid.uuid4()}"
    resolved_decision_ref = DecisionRef(
        artifact_type=DecisionArtifactType.APPROVAL_DECISION,
        artifact_id=decision_artifact_id,
        content_hash=hash_artifact(decision_artifact),
    )
    step("📦", f"ApprovalDecision artifact stored. content_hash={hexshort(resolved_decision_ref.content_hash)}")

    # The resolved row points at the ApprovalDecision (decision_ref) AND
    # at the pending row it supersedes (prior_audit_id).
    context_resolved = ExecutionContext(
        actor=actor,
        decision_ref=resolved_decision_ref,
        trigger_signal_ref=trigger_signal_ref,
        compliance_scope=[ComplianceScope.GDPR, ComplianceScope.NIS2],
    )
    result_act3 = await runner.execute(
        spec=spec_compliant, context=context_resolved, prior_audit_id=pending_audit_id
    )
    assert result_act3.outcome == ExecutionOutcome.DENIED
    step("✅", "Action terminally DENIED. Vendor-side : still nothing happened.")
    presenter_pause(
        "Final - chain verification",
        "Now the harness verifies the signed chain, then mutates one historical row to show tamper detection.",
    )

    # ======================================================================
    # FINAL — chain.verify() proves end-to-end integrity, then we tamper
    # ======================================================================
    banner("FINAL — Chain integrity")
    chain.verify()
    step("✅", f"chain.verify() OK — {len(chain.rows())} rows, all HMACs check out.")

    step("🧪", "Tampering with a single byte of the pending row's canonical_bytes...")
    chain.tamper_canonical_byte(2)  # Act II's approval/pending row
    try:
        chain.verify()
        step("❌", "Tamper not detected — this would be a serious bug.")
    except AuditChainBroken as exc:
        step("✅", f"AuditChainBroken raised as expected: {exc}")

    print()
    print("-" * 78)
    print("  Reading guide for the article :")
    print(f"  - {len(chain.rows())} signed rows across 3 acts, all linked by HMAC.")
    print("  - Act I (#1) : FAILURE + vendor_code=warlog.gdpr.pii_required, connector skipped.")
    print("  - Act II (#2,#3) : DRY_RUN success + APPROVAL pending. Connector never reached apply().")
    print("  - Act III (#4,#5) : DRY_RUN success + APPROVAL DENIED, prior_audit_id points at #3.")
    print("                       decision_ref points at the ApprovalDecision artifact.")
    print("  - Tamper attempt on row #3 broke verify() - exactly as designed.")
    print("-" * 78)


if __name__ == "__main__":
    asyncio.run(main())
