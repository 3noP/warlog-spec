# Changelog

> **Version reset for first public release.** Internal pre-publication
> development reached `0.5.0` across twelve milestones (see entries
> below). For the first public PyPI artifact we deliberately reset to
> `0.1.0` to honestly signal pre-1.0 stability and invite breaking
> changes during the public-feedback window. We do NOT use a `rc`
> suffix : v0.1 is an early experimental release, not a candidate for a
> v1.0 stable. Per semver, breaking changes between v0.1 and v0.2 are
> explicitly allowed. The internal `0.5.0` history is preserved here
> for transparency — none of it was ever published, so no external
> consumer is downgraded.

## [0.1.0] — 2026-05-20 — first public PyPI release

First artifact published to PyPI. Source moved from a private monorepo
to the public `github.com/3noP/warlog-spec` repository, with the
TypeScript reference package (`@warlog/spec`) released in lockstep at
the same version. The technical article *"What OpenTelemetry Doesn't
Capture About AI Agents (and How to Fix It)"* ships simultaneously.

### Released as part of this version

Twelve internal milestones (originally tagged `0.0.0` through `0.5.0`
in private) consolidate into this first public release. The contract
is ABI v1.0 with the full trust-layer surface — see the per-milestone
entries below for the historical decision trail. Highlights :

- Trust-layer additions on `AuditRow` : `decision_ref`,
  `trigger_signal_ref`, `compliance_scope`, and `actor.agent` when
  the actor is automation.
- `AuditActor` as a discriminated union of `HumanActor` and
  `AutomationActor` (the latter requires a populated `AiAgentRef`).
- `warlog_spec.provider_abi` exports : `AiAgentRef`, `AutomationActor`,
  `HumanActor`, `ComplianceScope`, `DecisionArtifactType`,
  `DecisionRef`, `TriggerSignalKind`, `TriggerSignalRef`.
- `warlog_spec.artifacts` exports : `RiskArbitration`,
  `RiskArbitrationPayload`, `ArbitrationAuthority`, `ArbitrationScope`,
  `AcceptedRisk`, `ApprovalDecision`, `ApprovalDecisionPayload`,
  `ResponseActionRequestRef`, `PolicyRef`.
- Reference runtime demo : `examples/rogue_agent_demo.py` — a
  self-contained ~200 SLOC reference runtime exercising the full
  trust-layer (GDPR gate, approval gate, HMAC chain, decision
  pointers) on a three-act "rogue agent" scenario.
- **Integration helper** (`warlog_spec.integrate`) — Pattern A audit
  decorator for AI agent tools. Exposes ``WarlogClient``, ``agent_run``
  context manager, and ``@audited`` decorator (sync + async). Reads
  ``WARLOG_*`` env vars with strict no-default policy on secrets ;
  pseudonymizes PII subjects automatically per the action catalog
  family ; synthesizes a deterministic ``DecisionRef`` per call so the
  AuditRow's required field is populated without forcing the caller to
  materialize a proposal ; resumes the chain after process restart via
  the persister's ``head_signature()`` API. ``JsonlFilePersister`` and
  ``InMemoryPersister`` ship as default implementations.
- **Approval gate as optional bouclier-actif** — the decorator accepts
  an optional ``ApprovalGate`` Protocol on the ``WarlogClient``. When
  injected, every audited call passes through the gate after dry_run
  and before apply. ``ApprovalDecision(state="pending")`` raises a
  typed ``ApprovalRequired`` exception with a populated ``request_id``
  and ``audit_id``, leaving an ``APPROVAL/PENDING_APPROVAL`` row in the
  chain ; ``state="denied"`` raises ``ApprovalDenied`` and emits an
  ``APPROVAL/DENIED`` row. The wrapped function is NEVER called when
  the gate blocks. The default (no gate) is audit-only — no APPROVAL
  row emitted, behavior unchanged for the 3-line quickstart.
- **Ephemeral HMAC secret support** — ``WarlogClient(hmac_secret=...)``
  now accepts either ``bytes`` (literal, held in memory the process
  lifetime) or ``Callable[[], bytes]`` (provider invoked per signed
  row, intended for HSM / Vault / KMS pulls). Reduces the time window
  an RCE on the process can extract a long-lived secret.
- **Clock-drift detection** — the client compares wall-clock against
  monotonic-clock between successive audit rows. Backward steps and
  divergence > 1 s (configurable via ``clock_drift_tolerance_s``)
  surface as ``RuntimeWarning``. The chain stays cryptographically
  valid (signatures commit to whatever timestamp was written) — the
  warning protects against silently-corrupted forensic ordering.
- **Multi-tenant persister safety check** — sharing a persister
  between two ``WarlogClient`` instances with different ``tenant_id``
  emits a ``RuntimeWarning`` at construction. Interleaving two
  tenants' chains in a single persister breaks per-tenant
  ``verify_chain`` because the rows are signed with different secrets.
- **Approval-gate misuse defenses** — gates returning a coroutine
  (async def request) raise a typed ``TypeError`` with a remediation
  hint ; gates returning a non-``ApprovalDecision`` value raise
  ``TypeError`` ; gates returning an unknown ``state`` value raise
  ``ValueError`` naming the actual state.
- **``propagate_warlog_context`` helper** — wraps a callable so the
  active ``agent_run`` context follows it across raw
  ``ThreadPoolExecutor.submit(fn)`` (the worker thread otherwise
  starts with a fresh context and audited functions raise
  ``TraceabilityError``). No-op for ``asyncio.to_thread`` /
  ``loop.run_in_executor`` which propagate contextvars by themselves.

### Conformance

- Smoke tests pass (`pytest packages/warlog-spec-py/tests/`).
- Cross-language byte equivalence with `@warlog/spec` 0.1.0
  verified against the pinned golden in
  `packages/warlog-spec-py/tests/test_canonical_row_bytes.py` (and the
  matching TS test at `packages/warlog-spec-ts/tests/audit-chain.test.ts`).
- Crypto path (`canonicalize_v1` + HMAC chain) is byte-stable since
  the first internal milestone — historical chains remain verifiable.

### Out of scope

- **Bundles** (`TriageBundle`, `InvestigationBundle`, `ResponseBundle`,
  `IncidentBundle`). Internal development carried them in
  `warlog_spec.bundles` ; before the first public release we moved
  them to backend-internal (`app.schemas.bundles`). Doctrine : these
  shapes describe how the Warlog console renders triage / investigation /
  incident screens — they are product-specific UI projections, not
  interop contract. The audit chain references no bundle ;
  `DecisionArtifactType` enumerates no bundle. A future RFC may
  re-promote a slimmed-down bundle interface if external adopters
  ask for one.
- Backend runtime (`AbiRunner`, `audit_chain_db`, Alembic) — operator's
  implementation. The reference runtime in `examples/rogue_agent_demo.py`
  is the canonical pattern.
- Asymmetric signature wire format (`Ed25519`, `RSASSA-PSS`) — RFC-0004
  ratified, schema-side support included, crypto code lands with the
  first operator who needs it.

---

## Internal pre-publication history

The entries below trace the twelve internal milestones that produced
the contract shipped in `0.1.0`. They were never published
externally — kept here as the historical decision trail.

## [Internal 0.5.0] — pre-publication (consolidated into 0.1.0)

Trust-layer additions to `warlog_spec.provider_abi` and
`warlog_spec.artifacts`. The spec is still pre-public so these land
in-place on ABI v1.0 rather than as a v2.0 bump ; the package version
stays at `0.5.0` until the first public release. See
`warlog-spec/CHANGELOG.md` for the full rationale.

### Added
- `warlog_spec.provider_abi` exports : `AiAgentRef`,
  `AutomationActor`, `HumanActor`, `ComplianceScope`,
  `DecisionArtifactType`, `DecisionRef`, `TriggerSignalKind`,
  `TriggerSignalRef`.
- `warlog_spec.artifacts` exports : `RiskArbitration`,
  `RiskArbitrationPayload`, `ArbitrationAuthority`,
  `ArbitrationScope`, `AcceptedRisk`, `ApprovalDecision`,
  `ApprovalDecisionPayload`, `ResponseActionRequestRef`,
  `PolicyRef`.

### Changed
- `AuditActor` is now a discriminated union
  (`Annotated[Union[HumanActor, AutomationActor],
  Field(discriminator="kind")]`) instead of a single concrete class.
  Code that instantiated `AuditActor(kind=..., id=...)` must switch
  to `HumanActor(id=...)` or `AutomationActor(id=...,
  agent=AiAgentRef(...))`.
- `AuditRow` requires four new fields : `decision_ref`,
  `trigger_signal_ref`, `compliance_scope`, and `actor.agent` when
  the actor is automation.

### Conformance
- 36 smoke tests pass (`pytest packages/warlog-spec-py/tests/`).
- Crypto path (`canonicalize_v1` + HMAC chain) is unchanged.

### Out of scope
- Backend (`AbiRunner`, `audit_chain_db`, Alembic) follow-up —
  next lot.

## [0.4.2] — 2026-05-07 — first standalone release

The Python reference package leaves the Warlog monorepo's app code and
becomes its own pip-installable artifact. Anyone — vendor, MSSP, OSS
contributor — can now `pip install warlog-spec` and write a connector
or a verifier without depending on the Warlog backend.

### Added
- `warlog_spec` Python package (Apache 2.0)
- Module surface :
  - `warlog_spec.enums` — 12 canonical workflow enums
  - `warlog_spec.provider_abi` — `ConnectorCapability`,
    `ResponseAction*`, `AuditRow`, `ConnectorError`, plus 10 supporting
    enums
  - `warlog_spec.pack_manifest` — `PackManifest`, `PackKind`,
    `TrustLevel`, full provenance shape
  - `warlog_spec.abi` — `AbiConnector` ABC + `ConnectorAbiError`
  - `warlog_spec.audit_chain` — HMAC primitives for verification
    (`canonicalize_v1`, `compute_genesis`, `compute_signature`)
  - `warlog_spec._base.SpecModel` — Pydantic camelCase base
- `examples/echo_connector.py` — full reference connector in 50 LOC,
  runnable standalone (`python examples/echo_connector.py`)
- `tests/test_smoke.py` — 9 smoke tests proving the package imports
  cleanly, round-trips through the camelCase wire format, the audit
  chain crypto matches, and the example connector runs end-to-end
- README — "Build a connector in 50 lines" + crypto-path-verify guide

### Aligned with
- Spec version `0.4.2` (the `warlog-spec/` repository)
- Same Pydantic models the Warlog reference runtime uses internally —
  third-party connectors importing this package interoperate with the
  runtime by construction
