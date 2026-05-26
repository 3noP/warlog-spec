# Changelog

All notable changes to Warlog Spec are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
spec follows [Semantic Versioning](https://semver.org/) — see
`VERSIONING.md` for the schema-specific semver semantics.

> **Historical-context references.** Some entries below cite
> ``docs/canon-migration/NN-*.md`` paths. These are internal design
> documents from the spec's pre-publication development that live in
> the private parent repository — they are not mirrored to this public
> repository. The narrative content in each CHANGELOG entry is
> self-contained ; the path references are kept verbatim for
> historical traceability inside the maintainer team. External
> adopters do not need them to understand the spec.

## [Unreleased]

### Added
- **3 follow-up RFCs accepted and implemented.** Closes the Open
  Questions of RFC-0001 :
  - [RFC-0002](rfcs/0002-ai-agent-ref-extensions.md) — `AiAgentRef`
    gains optional `subAgents`, `toolsManifestHash`,
    `retrievalContextRef`, `compositionKind` for multi-agent /
    tool-using / RAG-grounded agent attribution. Additive, v1
    single-agent rows unchanged. Implemented in both `warlog-spec-py`
    and `@warlog/spec`.
  - [RFC-0003](rfcs/0003-stix-projection.md) — outbound STIX 2.1
    projection of `CaseReturnSummary` to a Note SDO + optional
    `ExtractedIOC → Indicator` projection. Deterministic uuid5-derived
    ids for cross-tenant deduplication. New module
    `warlog_spec.stix_projection` (Python) + `stix-projection.ts`
    (TypeScript). 8 Python tests + 6 TS tests covering shape,
    determinism, confidence mapping, IOC pattern building.
  - [RFC-0004](rfcs/0004-asymmetric-signatures.md) — `AuditAttestation.algorithm`
    enum extends to `Ed25519` and `RSASSA-PSS-SHA256` alongside
    HMAC-SHA256. Schema change implemented in both packages ;
    crypto code paths land with the first operator that needs them.
    `signatureValue` constraint relaxed from `length=64` to
    `min=64, max=4096` to accommodate variable-length signatures.

### Added
- **`@warlog/spec` TypeScript reference implementation.** Second
  language for the spec, in `packages/warlog-spec-ts/`. Zod schemas
  + inferred TypeScript types for every shape, HMAC audit-chain
  primitives, and productible-type factories matching `warlog-spec-py`
  byte-for-byte. Cross-language byte equivalence enforced by
  `tests/audit-chain.test.ts` against a pinned golden shared with
  the Python canonicalization test. `COMPAT.md` claims Level 1 + 2
  for `@warlog/spec` with full productible-type coverage. This is
  what makes warlog-spec a standard candidate rather than a Python
  library.

### Removed
- **Bundle UI projection types** (`TriageBundle`, `InvestigationBundle`,
  `ResponseBundle`, `IncidentBundle`) are out of scope for the open
  spec. Internal development carried them, but they describe how a
  product's UI renders triage / investigation / incident screens —
  product-specific decisions, not interop contract. The audit chain
  does not reference any bundle ; `DecisionArtifactType` enumerates
  no bundle. The bundle shapes still exist in the Warlog backend
  (`app/schemas/bundles.py`) for that product's own UI consumption.
  Level 2 conformance now covers 18 productible types (was 22).

### Added
- **Ecosystem positioning documented + RFC process opened.** Two
  public documents land alongside the schemas :
  - `docs/ECOSYSTEM-MAPPING.md` — explicit position vs OCSF, STIX 2.1,
    OpenC2, CACAO, OSCAL, Sigma, and the MITRE family. Per-standard
    consume / translate / complement / embed verdict with concrete
    mapping tables.
  - `rfcs/README.md` + `rfcs/template.md` — RFC process docs
    (numbering, Draft → Last Call → Accepted → Implemented flow,
    approval thresholds, document structure).
  - `rfcs/0001-trust-layer.md` — first public RFC, retroactively
    documenting the trust-layer additions (decisionRef,
    triggerSignalRef, complianceScope, AiAgentRef, SignedAuditRow,
    RiskArbitration, ApprovalDecision, GDPR pseudonymization gate)
    with motivation, alternatives, design rationale, and references
    to EU AI Act / DORA / NIS2 / PCI DSS v4.0 / GDPR. Status :
    Accepted, Implemented.

  Both surfaces are intended to make the spec legible to external
  adopters before any v1.0 release. README updated to point at them
  from the landing page.

### Added
- **Industrial-grade hardening (pre-publication review).** Four
  improvements closing the gap between the trust-layer additions
  and a production-ready, third-party-implementable contract. Still
  in-place on ABI v1.0 ; spec stays pre-public so no version bump.

  1. **`SignedAuditRow` public schema + `AuditAttestation` envelope.**
     The HMAC chain attestation was previously visible only in the
     internal runtime path (``SignedAuditRow`` dataclass + DB columns).
     The public schema now publishes a JWS-style envelope so an
     AuditRow exported standalone is verifiable end-to-end :
     ``payload`` (the signed `AuditRow`) + ``attestation`` carrying
     ``prevRowHash`` (link to previous row, hex HMAC), ``signatureValue``
     (hex HMAC over canonical bytes), ``algorithm`` (literal
     ``HMAC-SHA256`` for now, extensible to Ed25519 / RSASSA later),
     ``canonicalizationFormat`` (literal ``v1``), and ``keyId``
     identifying the rotatable HMAC secret. A consumer with the
     matching secret recomputes the HMAC from the embedded payload
     and validates without store access. New schema
     ``provider-abi/signed-audit-row.json``. New canonical example
     ``examples/provider-abi/signed-audit-row.conformance.json``.

  2. **`DecisionArtifactType` → schema mapping (formalized).** The
     enum value → JSON Schema relationship was implicit by convention.
     Now published as ``provider-abi/decision-artifact-type-mapping.json``.
     A conformance test verifies the bidirectional completeness :
     every enum value MUST appear in the mapping, every mapping value
     MUST resolve to an existing schema, and inversely. Closes the
     "consumer guesses by convention" hole that would have re-introduced
     semantic lock-in.

  3. **`SelectorRepresentation` + GDPR pseudonymization gate.** New
     enum ``raw`` / ``sha256`` / ``sha256_salted``. ``ResponseSubject``
     gains ``selectorRepresentation`` (default ``raw``) and
     ``selectorKeyId``. Pydantic-side validator : non-raw representations
     REQUIRE a non-empty ``selectorKeyId``. Runtime enforcement : the
     ``AbiRunner`` rejects any action whose family is ``identity``,
     ``email``, or ``iam`` and whose selector is not ``sha256_salted``,
     with ``FailureCategory.POLICY`` and ``vendor_code='warlog.gdpr.pii_required'``,
     BEFORE the connector sees the request. Doctrine : actions
     touching PII selectors (user emails, principal names, account
     IDs) MUST be pseudonymized with a tenant-side rotatable salt ;
     salt rotation = de-facto erasure of pre-rotation rows without
     mutating the append-only chain. 5 new tests in
     ``backend/tests/unit/services/connectors/test_pii_pseudonymization.py``
     cover the four matrix cells (raw on PII rejected, sha256 alone
     still rejected, sha256_salted passes gate, non-PII family
     unaffected) + a Pydantic-side validator test.

  4. **`priorAuditId` on `AuditRow`.** Optional reference to the row
     this one supersedes in the same execution. Doctrine : populated
     when resolving a ``pending_approval`` row (the typical
     approve-then-apply lifecycle edge), letting consumers reconstruct
     the pending → resolved chain without correlating ``executionId``
     + ordering by hand. Empty elsewhere — soft doctrine, not enforced.

- **`canonicalize_v1` corrected to emit camelCase keys** (``by_alias=True``).
  The internal serialization was emitting snake_case while the
  published wire format is camelCase — this was a latent
  implementation bug surfaced when the canonical bytes pinning test
  was actually wired up (typo on the test function names meant pytest
  never collected them). Fixed in place because we are pre-public ;
  the canonical bytes ``_GOLDEN`` is repinned.

- **Trust-layer additions on `AuditRow` (still ABI v1.0).** Five
  additions that close the gap between the "Substrate / Runtime /
  Trust Layer" article and the actually-shipped contract. The audit
  chain now cryptographically links to the decision that motivated
  the action and the upstream signal that triggered it, tags the
  regulated perimeters it touched, and (when the actor is automation)
  carries the EU AI Act traceability of the agent that initiated it.
  Two new artifacts (`RiskArbitration`, `ApprovalDecision`) make the
  human, doctrinal substrate a first-class citizen of the contract.

  Since the spec is **still pre-public** (bootstrap phase, no
  external adopter pinned to a version), these additions land
  in-place on ABI v1.0 rather than as a v2.0 bump. The
  canonicalisation format (`canonicalize_v1`) is unchanged ;
  historical chains continue to verify against their stored canonical
  bytes by construction.
- **`ComplianceScope` enum.** Nine canonical regulated perimeters :
  `nis2`, `dora`, `pci_dss_v4`, `sox`, `hds`, `secnumcloud`, `hipaa`,
  `gdpr`, `iso_27001`. Multiple tags per `AuditRow` are valid.
  Audit queries can now answer "everything that touched the PCI CDE
  last quarter" without parsing free-form metadata.
- **`DecisionRef` + `DecisionArtifactType`.** Cryptographic pointer
  to the artifact that motivated an action. `contentHash` is sha256
  of the canonical-bytes serialization of the referenced artifact —
  an auditor can fetch the artifact by `artifactId` and confirm it
  has not been mutated since the audit row was signed. The
  `DecisionArtifactType` enum names the eleven canonical artifact
  shapes that can motivate an action (proposals, assessments,
  arbitrations, approval decisions, closure / case-return summaries).
- **`TriggerSignalRef` + `TriggerSignalKind`.** Cryptographic pointer
  to the upstream signal (OCSF event, alert, IOC, playbook tick) that
  motivated the action. `manual` is a first-class value — an analyst
  initiating an action without an upstream signal is a legitimate
  flow and the audit row MUST NOT pretend it had one.
- **`AiAgentRef` carried by `AutomationActor`.** When
  `actor.kind = "automation"`, the audit row carries
  `model`, `modelVersion`, `systemPromptHash` (sha256 of the canonical
  system prompt bytes, 64 hex chars), `agentRunId` (groups all
  actions emitted in one ReAct loop / decision-cycle), and an
  optional `reasoningArtifactRef` pointing at the persisted CoT /
  tool-call trace. This is the EU AI Act traceability anchor : an
  auditor can recompute why an agent chose this action from the
  pinned model identity + system prompt + reasoning artifact.
- **`RiskArbitration` artifact** (new `CanonicalArtifact`). Captures
  the signed, durable, doctrinal decision that pre-authorizes a
  class of actions on a scope until expiration. Fields :
  `authority{role, signerId, signerName}` (role ∈ ciso, dro, dpo,
  manager, senior_analyst, service_owner, other), `scope[]`,
  `acceptedRisks[]` (named risks instead of free-form rationale),
  `policyRef`, `validFrom`, `validUntil`, `justification`. The
  audit chain points at it via `DecisionRef` when an action
  executes under its arbitration.
- **`ApprovalDecision` artifact** (new `CanonicalArtifact`). Typed
  record of an effective approval decision, distinct from the
  request-side `ApprovalDescriptor` (which only declares what level
  is required). Fields : `requestRef{actionId, subjectKind,
  subjectValue, idempotencyKey}` (mirrors the originating
  `ResponseActionSpec`), `decisionMakerKind`, `decisionMakerId`,
  `decision` ∈ {approved, denied}, `decidedAt`, `basisRef`
  (policy / playbook / arbitration the decision was based on),
  `rationale`, optional `expirationOverride`. The audit chain
  points at it via `DecisionRef` when an action lands in the
  `apply` phase.
- **`PolicyRef` shared primitive.** Open `policyKind` vocabulary
  (`"playbook"`, `"policy_document"`, `"doctrine_kb"`,
  `"derogation"`, `"runbook"`, …) + `policyId` + optional `version`.
  Used by both `RiskArbitration.payload.policyRef` and
  `ApprovalDecision.payload.basisRef` so the substrate is not
  locked to a single doctrine-repository format.
- Two new canonical examples : `examples/artifacts/risk-arbitration.signed-derogation.json`,
  `examples/artifacts/approval-decision.senior-approved.json`. One
  new audit-row example : `examples/provider-abi/audit-row.automation.json`
  exercising the `AutomationActor` shape with AI-agent traceability.

### Changed
- **`AuditActor` is now a discriminated union** of `HumanActor` and
  `AutomationActor` instead of a single class with `kind:
  Literal["human", "automation"]`. Internal callers that did
  `AuditActor(kind="human", id=...)` must switch to
  `HumanActor(id=...)` or `AutomationActor(id=..., agent=...)`.
  JSON Schema emits a proper `oneOf` with discriminator `kind`, so
  the wire format change is purely structural (one extra `oneOf`
  layer ; the existing camelCase keys are preserved).
- **`AuditRow` gains four REQUIRED fields** : `decisionRef`,
  `triggerSignalRef`, `complianceScope`, and the `agent` field
  carried by `AutomationActor` when `actor.kind = "automation"`.
  Existing audit rows that do not carry these fields no longer
  validate. Acceptable because the spec is pre-public and there
  is no external adopter yet — internal call sites (`AbiRunner`,
  smoke tests, integration tests) get updated in a follow-up
  backend lot. `complianceScope` MAY be an empty list when the
  action is outside any tagged regulated perimeter ; producers
  must make the empty-vs-tagged decision explicitly rather than
  rely on a default.

### Conformance
- Level 1 (Read) : **9/9 examples validate** and **7/7 invalid
  fixtures are rejected** by their schemas
  (`python warlog-spec/tests/conformance/runner.py --level 1`).
- `warlog-spec-py` smoke tests : **36/36 pass**.
- Backend integration tests : **deferred to the backend-impl
  follow-up lot.** Existing tests instantiate `AuditActor(kind=...,
  id=...)` directly and build `AuditRow` without the new REQUIRED
  fields ; they need the runtime update to pass.

### Out of scope (next lot)
- **Backend runtime** : `AbiRunner` needs to gain the
  `decision_ref` / `trigger_signal_ref` / `compliance_scope`
  parameters and thread them through to every emitted `AuditRow`.
- **DB migration** : `connector_audit_chain` needs new promoted
  columns (`decision_ref_artifact_id`, `decision_ref_artifact_type`,
  `trigger_signal_kind`, `compliance_scope[]`) for indexable
  queries. The `row_payload` JSONB already holds the full row by
  construction.
- **`pending_approvals` → `ApprovalDecision` writer.** The existing
  trust boundary table should emit an `ApprovalDecision` artifact
  on every transition out of PENDING so the audit chain can point
  at it via `DecisionRef`.

### Added
- **Read-side Phase 2 follow-up (closes 3 review findings).** Three
  contract issues on the initial Phase 2 cut have been resolved in
  the same slice :
  - `CanonicalArtifact` base class introduced in
    `warlog_spec.artifacts`. `EnrichmentAssessment` and
    `MitreAssessment` now inherit from it ; `AbiEnricher.enrich`
    return type is `CanonicalArtifact | None` instead of the
    too-narrow `EnrichmentAssessment | None`. The descriptor's
    open `produces_artifact_types` vocabulary now matches the ABC
    return type — a connector advertising `"mitre.assessment"`
    can return a `MitreAssessment` through the public interface.
  - `EnrichmentRequest` model introduced. Carries `subject_type`,
    `subject_id` (`min_length=1`), and `target`. `AbiEnricher.enrich`
    signature changed from `enrich(subject)` to
    `enrich(request: EnrichmentRequest)`. The connector copies the
    subject attribution into the produced envelope — closes the
    "runtime stamps it from the calling alert" contract hole the
    initial cut had.
  - Reference `VirusTotalEnricher` updated to the new shape ; smoke
    tests verify the envelope's `subject_type` / `subject_id` are
    populated from the request, not stamped by the runtime.
- **Read-side Phase 2 — capability descriptor + enricher base
  class.** Wires the read-side data canon promoted in Phase 1 (audit
  17) to the connector capability layer and the runtime contract.
  Three new public surfaces :
  - `EnrichmentDescriptor` on `ConnectorCapability` — declares
    `produces_artifact_types`, `supports_entity_types`,
    `supports_ioc_types`, `freshness`, `bulk_lookup`. Empty default
    means "this connector does no read-side enrichment". Read-side
    analogue of `EgressDescriptor`.
  - `FreshnessHint` enum — `realtime` / `near_realtime` / `daily` /
    `weekly` / `unknown`. Hint for caching-policy decisions ; not a
    guarantee.
  - `AbiEnricher` ABC — read-side dual of `AbiConnector`. Lifecycle
    is `authenticate → enrich(subject) → EnrichmentAssessment | None`.
    No dry_run, no approval gate, no verify (the assessment IS the
    result), no idempotency_key requirement. A vendor doing both
    writes and reads can multiply-inherit `AbiConnector` and
    `AbiEnricher` on a single class or ship two separate classes.
- **Reference VirusTotal enricher** at
  `packages/warlog-spec-py/examples/virustotal_enricher.py` :
  ~350 LOC, real httpx code against VT API v3, vendor-shape →
  canonical-shape mapping in
  `_vt_response_to_assessment()` (last_analysis_stats / threat
  classification → typed `EnrichmentAssessment` with provenance,
  confidence band, citation pointing at the VT report id). Read-
  side equivalent of the seven write-side reference connectors.
- **JSON schema** `connector-capability.json` extended in lockstep
  with `enrichment` property + `EnrichmentDescriptor` /
  `FreshnessHint` definitions.

See `docs/canon-migration/18-readside-phase2.md`.

### Added
- **Read-side data canon promoted to the public spec (Phase 1).**
  The Provider ABI defines the WRITE-side vendor contract (verbs :
  `ResponseActionId`) ; the read side is contracted via DATA SHAPES,
  not verbs. Ten canonical types lifted from the Warlog backend into
  `warlog_spec.artifacts` so adopters can build enrichers against a
  typed, importable, camelCase-wired contract :
  `ArtifactProducer`, `ArtifactConfidence`, `ArtifactCitation`,
  `ArtifactEnvelope` (the unified read-side envelope —
  read-side analogue of `AuditRow` on the write side),
  `NormalizedEntity`, `ExtractedIOC`, `MitreMapping`,
  `MitreAssessment`, `AlternativeTechnique`,
  `EnrichmentAssessmentPayload`, `EnrichmentAssessment` (canonical
  output shape any enricher produces — VirusTotal / AbuseIPDB /
  Shodan / internal ML all fill the same envelope). Plus the
  canon-only enums `ConfidenceBand` and `ArtifactReviewState`.
  Backend `app/schemas/canonical.py` now re-exports from the
  package ; class identity is preserved (no duplication, locked
  by the new `test_backend_canonical_re_exports_share_class_identity`
  smoke test). See `docs/canon-migration/17-readside-promotion.md`
  for the architecture and guardrails (no `EnrichmentActionId`,
  no params_schema for reads, no HMAC chain for reads, no approval
  gate for reads). Phase 2 (`EnrichmentDescriptor` on
  `ConnectorCapability` + typed enricher base contract returning
  `ArtifactEnvelope` instead of `dict[str, Any]`) is queued for
  the next slice.

### Added
- **Doctrine refinement + 5 inverse-action additions (post-cloud-audit
  review).** Closes three High and two Medium findings on the cloud
  audit. The `ResponseActionReversibility.DISRUPTIVE` doctrine in
  `provider_abi.py` is sharpened : the test is "does vendor-side
  reversal exist", not "does our canon already ship the inverse
  action". Five inverse actions ship to keep the catalog symmetric :
  `host.start` (REVERSIBLE), `iam.role_attach` (REVERSIBLE),
  `iam.credentials_enable` (REVERSIBLE), `key.enable` (REVERSIBLE),
  `bucket.unlock` (REVERSIBLE). All cross-validated against AWS /
  Azure / GCP. Catalog grows from 44 → 49 actions.
  See `docs/canon-migration/16-doctrine-refinement.md`.

### Changed
- **`key.rotate` reclassified from DISRUPTIVE to REVERSIBLE.** Cloud
  KMS rotation is version-add semantics in AWS, Azure, and GCP : new
  primary version for new encrypts, old versions remain enabled for
  decrypt. There is no operational disruption — old encrypted data
  stays decryptable. The previous DISRUPTIVE classification was based
  on the (incorrect) assumption that consumers caching the old version
  break.
- **AWS connector materially fixed (v0.1.0 → v0.2.0).** Three High
  findings closed : (1) `key.rotate` now calls `RotateKeyOnDemand`
  (forces a new version *now*) instead of `EnableKeyRotation` (which
  only toggles the future annual auto-rotation — wrong semantic). (2)
  `iam.credentials_rotate` now surfaces the new ``SecretAccessKey``
  in `ResponseActionResult.details['vendor_secret_material']` ; the
  prior implementation dropped it on the floor, locking out the
  rotated principal. New config flag
  ``delete_old_after_rotation: bool = True`` for safety mode (keep
  old key Active during distribution). (3) STS AssumeRole moved from
  `__init__` to `authenticate` so credential errors flow through the
  runner's standard error mapping. Two Medium findings closed :
  `auth.model` corrected to `API_KEY` (AWS uses long-lived key pairs,
  not OAuth2), docstring corrected on `assume_role_arn` placement,
  removed bogus `ip.block`/`ip.unblock` mentions. Connector now
  advertises the full 14 cloud actions (9 + 5 inverses).

### Added
- **Cloud family audit (additive within ABI 1.0).** AWS-driven,
  cross-validated against Azure + GCP. Nine new `ResponseActionId`
  values across THREE NEW FAMILIES (`iam`, `key`, `storage`) plus
  device-family extension : `host.stop` (DISRUPTIVE — in-memory
  lost, disk preserved), `host.delete` (DESTRUCTIVE — instance
  terminated), `iam.role_detach` (DISRUPTIVE — in-flight assumed
  sessions live to expiry), `iam.credentials_disable` (DISRUPTIVE),
  `iam.credentials_rotate` (DESTRUCTIVE — old credential gone),
  `key.disable` (DISRUPTIVE — encrypted data inaccessible until
  re-enabled), `key.rotate` (DISRUPTIVE — cached consumers break),
  `key.schedule_deletion` (DESTRUCTIVE — past cooldown, decryption
  forever impossible), `bucket.lockdown` (DISRUPTIVE — public
  consumers break, reversible). Catalog grows from 35 → 44 actions.
  See `docs/canon-migration/15-cloud-gap-audit.md`.
- **Three new canonical params schemas** :
  `iam.role_detach.json` (required `policy_id` — abstracts AWS
  PolicyArn / Azure roleAssignmentId / GCP role tuple ; reused by
  `iam.role_attach`),
  `iam.credentials_disable.json` (required `principal_id` — AWS
  UserName, Azure object id, GCP service account email — reused by
  `iam.credentials_enable` and `iam.credentials_rotate` so the runner
  rejects malformed requests for ALL three credential-lifecycle
  actions before connector code runs),
  `key.schedule_deletion.json` (required `cooldown_days` 1-90 ; the
  connector clamps to the vendor's allowed range : AWS 7-30, Azure
  7-90, GCP 24h-30d, and surfaces the effective value in
  `vendor_message`).
- **Reference AWS multi-service connector** at
  `packages/warlog-spec-py/examples/aws_response_connector.py` :
  14 cloud actions across IAM / KMS / S3 / EC2 via boto3 (the
  realistic SDK for AWS — Sig V4 wrappers don't get hand-rolled in
  production). Auth via standard credential chain ; cross-account
  access via STS AssumeRole built lazily inside ``authenticate()``
  so credential errors flow through the runner's standard error
  mapping (see the doctrine-refinement changelog above for the
  pre/post-fix history).
- **Approval-defaults shift** : zero new cloud-IR-direction actions
  land at `analyst` level. Cloud IR is operationally a manager-level
  discipline by default — every primitive can break a downstream
  service if misfired. The five inverse-direction actions added in
  the doctrine refinement (`host.start`, `iam.role_attach`,
  `iam.credentials_enable`, `key.enable`, `bucket.unlock`) are
  REVERSIBLE and approval `analyst` (host.start) or `senior` (the
  other four) — restoring service is a lower-blast-radius direction.
  Catalog tally after the refinement :
  REVERSIBLE 27 ; DISRUPTIVE 8 ; DESTRUCTIVE 13 ; VARIES 1
  (= 49 total).

### Added
- **Runner-enforced canonical params validation.** Closes the residual
  gap flagged in the previous review : ``params_schema_ref`` is now
  consumed at runtime, not just published as a contract. The package
  ships :
  - ``warlog_spec.action_catalog.load_params_schema(action_id)`` —
    loads the bundled JSON Schema for an action's params, returning
    ``None`` for actions with no canonical schema.
  - ``warlog_spec.action_catalog.validate_params(action_id, params)``
    — raises ``ParamsValidationError`` on schema violation, no-op
    otherwise. Requires ``warlog-spec[verify]``.
  - The 3 per-action schemas (``host.collect_artifacts``,
    ``user.group_remove``, ``session.terminate``) are bundled inside
    the wheel at ``warlog_spec/_schemas/action-params/`` so the
    package is self-contained at runtime ; ``importlib.resources``
    resolves them regardless of install mode.
- **Backend ``AbiRunner`` validates params before ``connector.dry_run``.**
  Two connectors advertising the same ``action_id`` are now guaranteed
  to receive ``params`` matching the canonical schema. Validation
  failures surface as ``ResponseActionResult(outcome=FAILURE, error=
  ConnectorError(category=POLICY, vendor_code='warlog.params.invalid',
  vendor_message=<field-pointer messages>))`` — the audit row records
  WHICH field violated the contract before the connector ever saw the
  request. Backed by 4 new tests in
  ``tests/unit/services/connectors/test_abi_runner_params_validation.py``
  proving the connector's lifecycle hooks are NOT called on invalid
  params, while valid params (including vendor-specific extension keys
  permitted by ``additionalProperties: true``) reach the connector.
- **Backend pin tightened to ``warlog-spec[verify]``** so jsonschema
  is a hard transitive dependency for any environment running the
  Warlog runtime. The base ``warlog-spec`` package stays light for
  type-only consumers.

### Added
- **Catalog hardening (post-review).** Three follow-up findings closed :
  - **Unknown-action fallback tightened.** `StaticPolicyResolver`'s
    fallback for an `action_id` not in the catalog goes from
    `(MANAGER, 1)` to `(MANAGER, 2)`. The prior value was weaker than
    the catalog's own MANAGER-level discipline (every catalog entry
    at MANAGER level requires ≥2 reviewers, enforced by smoke test
    `test_action_catalog_entries_are_well_formed`). A connector
    advertising a brand-new action_id can no longer downgrade the
    four-eyes requirement.
  - **Cross-language drift guard.** Two safeties added against the
    Python registry diverging silently from the JSON manifest that
    Go/TS SDKs consume :
    1. `warlog_spec.action_catalog.to_json_manifest()` derives the
       canonical JSON shape from the Python registry. Maintainers
       run `python -m warlog_spec.action_catalog` (or call
       `to_json_manifest()` directly) to regenerate
       `warlog-spec/schemas/action-catalog.json` after any registry
       edit. The JSON is the derivation, the Python is the source.
    2. `test_action_catalog_json_in_sync_with_python_registry`
       smoke test compares every operational field of every action
       between the on-disk JSON and the freshly-generated dict. Drift
       fails CI ; the prose `description` field is allowed to vary.
  - **Duplicate-entry detection.** `_ENTRIES` is now scanned for
    duplicate `action_id` values BEFORE the dict is built. Without
    this, a copy-paste duplicate would be silently overwritten in
    `ACTION_CATALOG` while the helper iterators (`actions_by_family`,
    `actions_by_reversibility`) walk the raw tuple and visit BOTH
    copies, producing inconsistent behavior. Now the import fails
    with a precise error pointing at the duplicate value.

### Added
- **Canonical action catalog as executable contract.** Triggered by
  reviewer findings on the prior reversibility audit ("you enriched
  the vocabulary, not the contract"). The reversibility / approval-
  defaults metadata previously living only in prose now ships as a
  structured registry :
  - `packages/warlog-spec-py/src/warlog_spec/action_catalog.py` —
    Python registry exposing `ACTION_CATALOG: dict[ResponseActionId,
    ActionMeta]` plus `actions_by_family`, `actions_by_reversibility`,
    `default_approval_for`. Every `ResponseActionId` MUST have a
    catalog entry — import-time check fails fast on drift.
  - `warlog-spec/schemas/action-catalog.json` — canonical JSON
    artifact for cross-language SDKs (Go, TS) to derive identical
    approval defaults and reversibility classifications.
  - `warlog-spec/schemas/action-params/<action>.json` — typed param
    schemas for actions whose `params` are not free-form. Initial
    set : `host.collect_artifacts.json` (artifact_type + path),
    `user.group_remove.json` (group_id required), `session.terminate.json`
    (session_type ∈ flow/vpn/ztna). Closes the gap where two
    connectors could advertise the same action with incompatible
    `params` shapes.
- **Backend `StaticPolicyResolver` derives from the catalog.** The
  hand-maintained `DEFAULT_MAP` is replaced by
  `_default_map_from_catalog()`, eliminating the drift the reviewer
  flagged (the prior map covered only 9/35 actions and described
  HOST_ISOLATE as "reversible" while audit 14 had re-classified it
  as DISRUPTIVE). Tenant overrides still layer on top via the
  `overrides=` constructor argument; the catalog is the floor, not
  the ceiling. Doctrine : tighter approval defaults flow from a
  single edit to the catalog to every consumer.

### Added
- **`ResponseActionReversibility.DISRUPTIVE` (additive within ABI 1.0).**
  Fourth value in the reversibility enum, distinguishing "an inverse
  action exists, but in-flight state is destroyed" (e.g.
  `host.isolate` drops live TCP sessions ; `host.restart` kills
  in-memory state) from clean reversible actions and from genuinely
  destructive ones. Driven by a cross-catalog reversibility re-audit
  that found 9 actions previously marked `REVERSIBLE` but
  operationally `DESTRUCTIVE` (e.g. `user.force_logout`,
  `user.reset_mfa`, `user.revoke_tokens`, `user.reset_password`,
  `process.kill`) and 3 marked `REVERSIBLE` but operationally
  `DISRUPTIVE` (`host.isolate`, `host.restart`, `user.disable`).
  Corrected classification + four-state model documented in
  `docs/canon-migration/14-reversibility-audit.md`. Catalog action
  count unchanged (35) ; tally shifts from 28 reversible / 5
  destructive to 22 reversible / 3 disruptive / 9 destructive / 1
  varies. Approval-policy defaults tightened accordingly.

### Added
- **Email family extended (additive within ABI 1.0).** Three new
  `ResponseActionId` values surfaced by the Proofpoint gap audit and
  cross-validated against M365 Defender for Email, Mimecast, Cisco
  Email Security, and Google Workspace : `email.block_sender` and
  `email.unblock_sender` (sender-side policy primitives, distinct
  from message-side quarantine/recall — block/unblock pair non-
  negotiable per the network-audit doctrine), `email.release`
  (inverse of `email.quarantine`, completes the round-trip so
  compliance audit chains show "quarantined → released after analyst
  review" as canonical events). Catalog grows from 32 → 35 actions.
  See `docs/canon-migration/12-email-gap-audit.md`.
- **Reference Proofpoint connector** at
  `packages/warlog-spec-py/examples/proofpoint_connector.py` :
  5 email actions across TAP (sender-side block/unblock) and TRAP
  (quarantine/recall/release).
- **Reference Zscaler ZIA/ZPA connector** at
  `packages/warlog-spec-py/examples/zscaler_zia_connector.py` :
  7 actions purely from existing canon. The Zscaler audit produced
  a **negative result** (zero new ResponseActionId values) — recorded
  in `docs/canon-migration/13-zscaler-no-extension.md` because
  negative results are evidence the canon is well-shaped (a different
  vendor class — cloud-delivered SSE — fits the same primitives as
  on-prem PAN-OS without strain).
- **Network family extended (additive within ABI 1.0).** Five new
  `ResponseActionId` values surfaced by the Palo Alto PAN-OS gap
  audit and cross-validated against Cisco Firepower, Fortinet
  FortiGate, Check Point, and OpenC2 SLPF: `ip.unblock`,
  `domain.unblock`, `url.unblock`, `hash.unblock` (FP resolution
  inverses, all clean OpenC2 SLPF `allow` mappings except hash),
  `session.terminate` (drop active TCP/UDP flow OR VPN tunnel —
  parameterized via `params['session_type']` ∈ `{flow, vpn}` ;
  distinct from `user.force_logout` which is identity-layer).
  Catalog grows from 27 → 32 actions. See
  `docs/canon-migration/11-network-gap-audit.md`.
- **Reference Palo Alto PAN-OS connector** at
  `packages/warlog-spec-py/examples/palo_alto_panos_connector.py` :
  7 actions via Dynamic Address Group tagging (User-ID XML, no
  commit needed) + custom URL category EDL + XML operational
  commands for session termination. Falcon connector extended to
  12 actions with the new unblock variants.
- **Device family extended (additive within ABI 1.0).** Three new
  `ResponseActionId` values surfaced by the CrowdStrike Falcon gap
  audit and cross-validated against Microsoft Defender for Endpoint,
  SentinelOne, and Carbon Black: `host.restart` (reboot device),
  `host.collect_artifacts` (file pull or memory dump for forensics —
  `params['artifact_type']` ∈ `{file, memory}`), `hash.block`
  (fleet-wide SHA256 prevention IOC, distinct from path-based
  `file.quarantine`). Catalog grows from 24 → 27 actions.
  See `docs/canon-migration/09-device-gap-audit.md`.
- **Prior-art mapping table** in `docs/canon-migration/10-prior-art-mapping.md`
  documenting how Warlog Spec sits relative to OCSF, STIX 2.1,
  CACAO, and OpenC2. Includes a per-action OpenC2 mapping table
  (11 direct, 6 partial, 10 outside OpenC2 scope) and bidirectional
  embedding examples for adopters already on OpenC2.
- **Identity family extended (additive within ABI 1.0).** Six new
  `ResponseActionId` values surfaced by the Okta gap audit and
  cross-validated against Azure AD, Google Workspace, and on-prem AD:
  `user.revoke_tokens` (kills OAuth/refresh tokens — distinct from
  `user.force_logout` which only kills sessions),
  `user.reset_password` (admin-initiated reset),
  `user.expire_password` (force change at next login),
  `user.unlock` (clear lockout state, distinct from `user.disable`),
  `user.group_remove` (privilege containment via group membership
  removal — requires `params['group_id']`),
  `user.delete` (destructive cleanup of attacker-created accounts).
  Catalog grows from 18 → 24 actions. See
  `docs/canon-migration/08-identity-gap-audit.md` for the full
  vendor-neutrality audit and the gap-audit template applied to
  subsequent vendor families.
- **Reference vendor connectors** under `packages/warlog-spec-py/examples/`:
  `okta_user_response_connector.py` (9 identity actions against
  Okta REST API with SSWS auth), `crowdstrike_falcon_connector.py`
  (5 EDR actions against Falcon API with OAuth2 client_credentials).
  Both written from public vendor docs; runtime-test against live
  tenants is the next step. PRs welcome.

### Changed
- 4 JSON Schemas (`response-action-spec`, `response-action-result`,
  `connector-capability`, `audit-row`) extended with the new identity
  enum values in lockstep with the Pydantic enum. ABI_VERSION stays
  `1.0` since this is additive within the major.

## [0.4.2-py] — 2026-05-07 — first installable Python reference package

The ABI exits "philosophy" status. The Python reference implementation
is now an installable, importable package (`pip install warlog-spec`)
with its own LICENSE, README, examples, and smoke tests. Anyone can
write a conformant connector against it without depending on the
Warlog backend.

### Added
- New top-level directory `packages/warlog-spec-py/` :
  - `pyproject.toml` (Apache 2.0, Pydantic-only deps, hatchling build)
  - `src/warlog_spec/` — public Python package with submodules
    `enums`, `provider_abi`, `pack_manifest`, `abi`, `audit_chain`,
    `_base`. `__init__.py` re-exports the full public surface.
  - `examples/echo_connector.py` — 50-LOC reference connector,
    runnable standalone (`python examples/echo_connector.py`)
  - `tests/test_smoke.py` — 10 tests proving package imports cleanly,
    audit chain crypto round-trips, and the example connector runs
    end-to-end without a runtime
  - `README.md` — "Build a connector in 50 lines" + crypto-path-verify
    guide
  - `CHANGELOG.md` (in package), `LICENSE` (Apache 2.0)

### Changed
- **Backend now consumes `warlog_spec` instead of duplicating types.**
  `app/canon/enums.py`, `app/canon/provider_abi.py`,
  `app/canon/pack_manifest.py`, and `app/services/connectors/abi.py`
  are now thin re-export layers over `warlog_spec.*`. Backend
  `pyproject.toml` declares `warlog-spec>=0.4.2` as a dependency.
- `app/services/connectors/audit_chain.py` keeps the runtime façade
  (`AuditChain`, `AuditChainStore`, `InMemoryAuditChainStore`,
  `SignedAuditRow`) but imports the crypto primitives
  (`canonicalize_v1`, `compute_signature`, `compute_genesis`,
  `AuditChainBroken`) from `warlog_spec.audit_chain`. Single source
  of truth for the byte-stable canonicalization.

### Conformance
- 10 standalone smoke tests on the package pass (`pytest tests/`).
- 100 backend tests still green after the refactor (canon, connectors,
  audit chain DB, outbox emit, models). No behavioural drift.
- `warlog/backend` Levels 1, 2, 4 maintained for spec `0.4.2`. The
  backend now documents its conformance via the same package a third
  party would install.

### Why this matters
A spec without an installable reference implementation is a slide
deck. With this release, a vendor / MSSP / OSS contributor can :
1. `pip install warlog-spec` (locally for now, PyPI once stabilized)
2. Subclass `AbiConnector`, declare a `ConnectorCapability`
3. Implement `apply()` that talks to their vendor API
4. Run their connector against any Warlog-compatible runtime

That's the line between thesis and standard.

### Out of scope (next slice)
- PyPI publication (requires spec to leave bootstrap, target v1.0.0)
- `warlog-spec-go` and `@warlog/spec` for cross-language parity
- Hosted JSON Schemas at stable URLs (`https://warlog-spec.dev/schemas/v0.4/...`)
- Conformance test runner shipped as `python -m warlog_spec.conformance`

## [0.4.2] — 2026-05-06 — outbox emission for terminal outcomes

The ABI runtime now matérialises terminal outcomes externally as
`capability.executed` `fact` events on the existing transactional
outbox. Audit row + outbox row land in the **same SQLAlchemy session**
so a rollback drops both together — outbox can never exist without the
audit row, and vice versa.

### Added
- `EVENT_TYPE_CAPABILITY_EXECUTED = "capability.executed"` constant +
  payload builder
  ([`backend/app/services/connectors/outbox_emit.py`](../backend/app/services/connectors/outbox_emit.py)).
  The event type was already declared as `fact` in
  `_EVENT_KIND_MAP` — Phase 0 left the slot ready, this slice fills it.
- `TerminalOutboxEmitter` Protocol + two impls :
  - `CapabilityExecutedOutboxEmitter(session)` — production emitter,
    enqueues via existing `OutboxService` on the same session as the
    audit chain store. Single transaction, single commit.
  - `NullOutboxEmitter` — no-op default for tests / dev runtimes
    without an outbox.
- `AbiRunner._finalize(...)` helper centralizes the
  cache + emit decision: cache only on terminal, emit only on terminal.
  Replaces inline `_cache_if_terminal` calls at every return point.
- `AbiRunner._emit(...)` now returns the `SignedAuditRow` it just
  appended, so the runner can correlate the terminal audit row to the
  outbox event identity (`payload.event_id == audit_id`).
- 13 new unit tests
  ([`tests/unit/services/connectors/test_outbox_emit.py`](../backend/tests/unit/services/connectors/test_outbox_emit.py))
  via a `RecordingEmitter`. Covers : SUCCESS / FAILURE / DENIED /
  dry_run-only emit once ; PENDING_APPROVAL never emits ; pending →
  approved sequence emits exactly once on the terminal pass ;
  idempotency cache hit does NOT re-emit ; payload identity
  (`event_id == audit_id`) ; default `NullOutboxEmitter` keeps runner
  silent.
- 4 integration tests
  ([`tests/integration/test_outbox_emit_db.py`](../backend/tests/integration/test_outbox_emit_db.py))
  against real `db_session` + `DbAuditChainStore` +
  `CapabilityExecutedOutboxEmitter`. Covers : same-session write of
  audit + outbox ; PENDING writes audit but no outbox event ;
  rollback drops both atomically (the same-transaction claim) ; event
  identity round-trips through the DB.

### Hard guarantees enforced
- **Terminal-only.** `PENDING_APPROVAL` never emits. Cached
  re-invocations never re-emit.
- **Same transaction.** Audit row + outbox row added before any
  commit. The atomicity test rolls back and observes both rows
  vanishing.
- **Stable, dedupable identity.** `payload.event_id ==
  signed.row.audit_id`. At-least-once delivery collapses for consumers
  keying on `event_id`.
- **Replay-safe.** Outbox row carries `outcome` + `audit_id`, never an
  instruction to re-execute. Worker republishing it does NOT trigger a
  second connector apply — the outbox is downstream notification only.

### Conformance
- `warlog/backend` Levels 1, 2, 4 maintained for spec `0.4.x`. Public
  spec unchanged (Pydantic shapes published in `warlog-spec/schemas/`
  not affected). The outbox event payload contract is internal /
  Phase 3 documentable as a public surface when external consumers
  exist.

## [0.4.1] — 2026-05-06 — audit chain hardening (review pass)

Targeted review before adding outbox emission (#3). Splits the audit
chain's cryptographic path from the queryable path so Pydantic schema
evolution can no longer false-positive integrity checks on historical
rows. The Alembic migration is amended (it had not yet been applied in
production) so no backfill is required.

### Added
- Canonical bytes are now persisted alongside the signature
  (`connector_audit_chain.canonical_bytes` BYTEA + `canonicalization_format`
  String). `AuditChain.verify` recomputes HMAC over the stored bytes
  rather than re-serializing the Pydantic `AuditRow`. Schema drift in
  `AuditRow` is decoupled from chain integrity.
- `CANONICALIZATION_FORMAT_V1` constant + `canonicalize_v1` function.
  Format identifier is **separate** from `AuditRow.spec_version` — the
  spec can evolve without rotating the cryptographic format and vice
  versa. A future `canonicalize_v2` (e.g. CBOR) lands alongside; old
  `v1` rows verify against `v1` regardless of what the current writer
  emits.
- `connector_audit_chain` gets `idempotency_key` column + index
  (`ix_connector_audit_chain_idempotency`). Ops queries like "all
  lifecycle attempts for this idempotency_key" now hit a real index
  instead of a JSONB scan.
- `DemoEdrConnector` now actually demonstrates the vendor-side
  idempotency contract documented in `AbiConnector.apply` : it tracks
  `_applied_idempotency_keys` and short-circuits duplicate applies the
  way real EDR / IAM APIs do (CrowdStrike Falcon, SentinelOne, etc.).
  Two new tests assert the contract holds even across state-conflict
  guards.
- Writer-stability tripwire test
  (`test_canonical_row_bytes_is_stable_for_pinned_payload`) repurposed:
  it no longer claims to protect historical chains (the persisted bytes
  do that now); it protects the **current writer's** byte stability
  against accidental drift.
- Tamper-detection tests split:
  - `test_row_payload_mutation_does_not_falsely_flag_tampering` —
    mutating the JSONB display surface does NOT break verification
    (cryptographic path is independent).
  - `test_verify_detects_canonical_bytes_tampering` — flipping a byte
    in the signed payload IS detected.

### Changed
- `compute_signature(prev_hash, row, secret)` →
  `compute_signature(prev_hash, canonical_bytes, secret)`. Operates on
  raw bytes; callers compute the bytes via `canonicalize_v1`.
- `SignedAuditRow` dataclass gains `canonical_bytes` and
  `canonicalization_format` fields. Both stores (`InMemoryAuditChainStore`,
  `DbAuditChainStore`) round-trip them.
- Documented in `AbiRunner` module docstring : `spec.expires_at` is a
  producer-side hint that the runner does NOT enforce. A reaper job in
  Phase 3 will flip pending rows to `expired` before approval is
  possible.

### Conformance
- `warlog/backend` retains Levels 1, 2, 4 claims for spec `0.4.x`. The
  hardening is internal — the public spec (Pydantic shapes published in
  `warlog-spec/schemas/`) did not change. Conformance Level 1 still
  passes 6/6 examples.

## [0.4.0] — 2026-05-06 — audit chain durability

The HMAC-signed audit chain is no longer in-memory only. A
DB-backed store persists every signed `AuditRow` to the new
`connector_audit_chain` table. The runtime is now defendable in
exploitation, not just plausible in test.

### Added
- Alembic migration
  [`20260506_0300_connector_audit_chain.py`](../backend/alembic/versions/20260506_0300_connector_audit_chain.py)
  — creates `connector_audit_chain` table. Append-only by convention
  (the ORM exposes no UPDATE/DELETE surface). Indexed on
  `(tenant_id, chain_seq)` (unique), `(tenant_id, execution_id)`,
  `(tenant_id, action_id, phase)`. Per-row JSONB payload stores the
  full `AuditRow` serialization for lossless round-trip.
- ORM model
  [`backend/app/models/connector_audit_chain.py`](../backend/app/models/connector_audit_chain.py)
  — `ConnectorAuditChainRow`. Inherits directly from `Base` (not
  `BaseModel`) because its primary key is the runtime-supplied
  `audit_id`, not an autogenerated UUID, and the only timestamp is
  `appended_at`.
- `DbAuditChainStore`
  ([`backend/app/services/connectors/audit_chain_db.py`](../backend/app/services/connectors/audit_chain_db.py))
  — drop-in implementation of `AuditChainStore`. Concurrency-safe per
  tenant via `SELECT ... FOR UPDATE` on the latest row before INSERT;
  unique constraint on `(tenant_id, chain_seq)` is the last-line guard
  against interleaved writers.
- 8 integration tests under
  [`backend/tests/integration/test_audit_chain_db_store.py`](../backend/tests/integration/test_audit_chain_db_store.py)
  hitting a real `db_session` fixture (SQLite in-memory by default,
  PostgreSQL when `USE_POSTGRES=1`):
  - genesis link on first append + signature link on subsequent appends
  - monotonic `chain_seq` per tenant
  - per-tenant chain isolation
  - verify passes for intact chain
  - verify detects payload tampering (mutated `outcome` in the JSONB)
  - secret rotation invalidates existing chain
  - drop-in equivalence : same chain content via `InMemoryAuditChainStore`
    and `DbAuditChainStore` produces byte-identical signatures

### Conformance
- `warlog/backend` Level 4 claim is now backed by a durable, verifiable
  audit chain (not just an in-memory chain that vanishes on restart).
  Operationally defendable: an auditor can recompute every HMAC by
  re-walking the table from `chain_seq=0`.

### Out of scope (next slice)
- Outbox emission of `capability.executed` after each terminal outcome.
  Lets downstream workers (metrics, notifications, secondary stores)
  react. Lands as Track B-3 — last item before a real vendor connector
  is acceptable to wire in.
- A real vendor connector — still gated on accessible test endpoint.
- Pack manifest install runtime + signature verify (Track C) — only
  starts once the vendor connector has actually traversed the ABI in
  production-ish conditions.

## [0.3.0] — 2026-05-06 — approval wiring (trust boundary)

The ABI runtime now has a real, durable trust boundary before any
side-effecting `apply` lands. The legacy `pending_approvals` table
(originally written for the playbook approval workflow) becomes the
shared substrate; the ABI runner gets a typed `ApprovalGate` integration
and a new non-terminal `ExecutionOutcome.PENDING_APPROVAL` status.

### Added
- New `ExecutionOutcome.PENDING_APPROVAL` value (additive — MINOR bump
  per `VERSIONING.md`). Non-terminal: the runner does **not** cache the
  result under the idempotency key, so callers can re-poll the gate
  after the out-of-band decision lands.
- `ApprovalDecision` is now a typed dataclass with `state ∈ {approved,
  denied, pending}` plus `request_id`. Replaces the prior `approved:
  bool` shape. Existing `AutoApproveGate` / `AutoDenyGate` keep the same
  external API; `AutoPendingGate` is added for the pending path.
- `DbBackedApprovalGate`
  ([`backend/app/services/connectors/approval/db_gate.py`](../backend/app/services/connectors/approval/db_gate.py))
  — production gate. INSERT into `pending_approvals` with the action_id
  + subject + idempotency_key as the dedup metadata. Re-invocations with
  the same key reuse the existing row's status.
- `StaticPolicyResolver` with the default catalogue : `alert.acknowledge`
  → auto-approve, reversible host actions → analyst approval, dangerous
  identity actions → senior, unknown actions default to manager (Safe by
  Design).
- `PendingApproval` SQLAlchemy model
  ([`backend/app/models/pending_approval.py`](../backend/app/models/pending_approval.py))
  — typed ORM surface for the existing table created by Alembic
  `20260415_0100_add_pending_approvals.py`. No schema change.
- `_TERMINAL_OUTCOMES` discipline in `AbiRunner`: idempotency cache
  writes go through `_cache_if_terminal`, which silently drops
  PENDING_APPROVAL. Tested explicitly :
  `test_pending_approval_is_not_cached_so_re_invoke_can_progress`.

### Changed
- `AbiRunner` approval handling is now tri-state (approved / denied /
  pending) instead of bi-state. Audit row at the APPROVAL phase carries
  the matching outcome (SUCCESS / DENIED / PENDING_APPROVAL).
- `app/canon/__init__.py` no longer eagerly re-exports `provider_abi` /
  `pack_manifest` symbols. Consumers MUST import directly from those
  submodules. The previous re-exports created an import cycle through
  `app/schemas/__init__.py` → `app/schemas/alert.py` → partial
  `app/models/alert.py` that surfaced once `PendingApproval` was added
  to `app/models/__init__.py`. Documented in the package docstring.

### Conformance
- 10 new tests under
  [`backend/tests/unit/services/connectors/test_db_approval_gate.py`](../backend/tests/unit/services/connectors/test_db_approval_gate.py)
  + 2 new tests under
  [`backend/tests/unit/services/connectors/test_abi_runner_demo_edr.py`](../backend/tests/unit/services/connectors/test_abi_runner_demo_edr.py).
  Total connector test count : 28 → 30 → no regressions.
- `warlog/backend` Level 4 claim now gated by both DemoEDR (in-tree
  reference) **and** the trust boundary (DbBackedApprovalGate). Real
  vendor connectors will inherit both.

### Out of scope (next slice)
- DB persistence of `AuditRow` — Alembic migration `connector_audit_chain`
  table + `DbAuditChainStore` impl. Audit chain still in-memory for
  prod-equivalent use (HMAC unchanged, store interface only).
- Outbox emission of `capability.executed` after each terminal outcome.
- A real vendor connector — deferred until an accessible test endpoint
  exists. The interface posed here is "vendor-ready" : transport,
  auth, error mapping, config schema, contract tests.

## [0.2.0] — 2026-05-06 — provider ABI runtime

The Provider ABI is no longer just a schema. The reference implementation
now executes a full action lifecycle through it on a built-in connector.
Track B milestone : "backend executing ≥1 real ABI" — achieved.

### Added
- **`AbiConnector`** abstract base class
  ([`backend/app/services/connectors/abi.py`](../backend/app/services/connectors/abi.py))
  — typed lifecycle (authenticate / dry_run / apply / verify) consuming
  `ResponseActionSpec`, returning `ResponseActionResult`.
- **`AbiRunner`** orchestrator
  ([`backend/app/services/connectors/abi_runner.py`](../backend/app/services/connectors/abi_runner.py))
  — full lifecycle dry_run → approval → apply → verify → audit, with
  pluggable approval gate, in-memory idempotency cache, and explicit
  failure-category mapping. Catches arbitrary exceptions and degrades to
  `FailureCategory.TRANSIENT`.
- **`AbiConnectorRegistry`** — process-global registry indexing connectors
  by id and by supported `ResponseActionId`. Used by the runner to route
  actions when no explicit `connector_id` is provided.
- **`AuditChain`** with HMAC-SHA256 chained signing
  ([`backend/app/services/connectors/audit_chain.py`](../backend/app/services/connectors/audit_chain.py))
  — append-only, per-tenant. Rotates the secret invalidates the chain
  (verifiable via `chain.verify(tenant_id)`). In-memory store ships now;
  DB-backed store + Alembic migration land with Track C (registry).
- **`DemoEdrConnector`** built-in
  ([`backend/app/services/connectors/builtin/demo_edr.py`](../backend/app/services/connectors/builtin/demo_edr.py))
  — Terraform-`null_provider`-style reference connector implementing
  `host.isolate`, `host.unisolate`, `alert.acknowledge`. Supports
  `simulate_failures` injection for every `FailureCategory` so the ABI's
  failure model is tested end-to-end.
- New canonical example
  [`response-action-result.host-isolate-success.json`](examples/provider-abi/response-action-result.host-isolate-success.json).
- 18 unit tests under
  [`backend/tests/unit/services/connectors/`](../backend/tests/unit/services/connectors/)
  covering : full lifecycle, all 5 failure categories (auth, not_found,
  state_conflict, transient, policy), denial path, dry_run-only,
  routing via capability, idempotency, audit chain integrity, tamper
  detection, secret rotation invalidation, per-tenant isolation.

### Conformance bumps
- `warlog/backend` claims **Levels 1, 2, 4 (Provider, via demo-edr)**
  for spec `0.2.0`. Level 4 is gated on a real connector exercising the
  ABI; the in-tree `demo-edr` qualifies. Production vendor connectors
  (CrowdStrike Falcon, SentinelOne, Defender) land incrementally and
  inherit Level 4 via the same runtime.

### Out of scope (next slice)
- DB persistence of `AuditRow` (Alembic migration `connector_audit_chain`
  table) — Track C
- Real vendor connector (CrowdStrike Falcon recommended for first) —
  next session
- Wiring `AbiRunner` into the existing capability proposal flow + outbox
  events — integration step
- Registry install runtime + signature verify — Track C

## [0.1.0] — 2026-05-06 — first schemas

First spec release with real JSON Schemas extracted from the reference
implementation (`warlog/backend`). Phase 2 milestone : "spec repo with
real schemas + at least one canonical example per artifact".

### Added
- 32 JSON Schemas auto-generated from canonical Pydantic models via
  `backend/scripts/generate_spec_schemas.py`. Layout:
  - `schemas/common/` — 10 enum schemas (severity, status, verdict,
    source, category, case-status, case-priority, entity-type,
    entity-role, ioc-type)
  - `schemas/envelopes/` — `artifact-envelope`, `proposal-envelope`
  - `schemas/artifacts/` — classification/mitre/enrichment assessments,
    closure/case-return summaries
  - `schemas/proposals/` — triage / next-step / playbook-candidate /
    investigation-summary proposals
  - `schemas/bundles/` — triage / investigation / response / incident
  - `schemas/provider-abi/` — `connector-capability`,
    `response-action-spec`, `response-action-result`, `audit-row`,
    `connector-error` (Phase 2 ABI draft → first concrete schemas)
  - `schemas/registry/` — `pack-manifest` (Phase 3 registry seed)
  - `schemas/manifest.json` — index of all published schemas
- 5 canonical examples in `examples/`:
  - `bundles/triage-bundle.full.json` (realistic EDR detection)
  - `provider-abi/connector-capability.sentinelone.json`
  - `provider-abi/response-action-spec.host-isolate.json`
  - `provider-abi/audit-row.success.json`
  - `registry/pack-manifest.warlog-certified-ransomware-response.json`
- Conformance runner skeleton in `tests/conformance/runner.py`. Level 1
  (Read) implemented against `jsonschema` lib. Level 2-4 stubbed.
- Provider ABI Pydantic models in `backend/app/canon/provider_abi.py` :
  `ConnectorCapability`, `ResponseActionSpec`, `ResponseActionResult`,
  `AuditRow`, `ConnectorError`, plus 10 supporting enums (18 atomic
  response actions, 4 auth families, 5 failure categories, …).
- Pack manifest Pydantic model in `backend/app/canon/pack_manifest.py` :
  `PackManifest`, 5 pack kinds, 3 trust levels, full provenance shape.

### Conformance
- `warlog/backend` reference implementation now claims Level 2 (Write)
  for all 32 published schemas — schemas were extracted from its
  Pydantic models so round-trip is guaranteed by construction.
- `warlog/frontend` claims Level 1 (Read) — `generated.ts` is regenerated
  from the same OpenAPI feeding the schemas.
- See `COMPAT.md` matrix.

### Out of scope
- Pack signature verification runtime (Phase 3)
- Connector ABI runtime / dispatcher (Phase 2 next step)
- Pack install flow + air-gapped bundle format (Phase 3)
- First-party Warlog Certified packs (Phase 3 — Track D)

## [0.0.0] — 2026-05-06 — bootstrap

Initial public skeleton of `warlog-spec/`. **No schemas published yet.**

### Added
- `README.md` — thesis, OCSF/STIX/Sigma positioning, governance intent
- `VERSIONING.md` — semver policy applied to schema spec, deprecation rules,
  bootstrap-phase semantics, test target doctrine
- `GOVERNANCE.md` — BDFL → Technical Committee (target v1.0.0) →
  foundation move (CNCF / LF Cybersecurity / OASIS)
- `CONTRIBUTING.md` — RFC process, CLA requirement, review thresholds
- `COMPAT.md` — separated reference implementations (pre-conformance)
  from the conformance matrix (empty until tests exist)
- `CHANGELOG.md` — this file
- `LICENSE` — Apache 2.0 (matches OCSF, OpenAPI Specification conventions)
- `schemas/` — empty placeholder
- `examples/` — empty placeholder
- `tests/conformance/` — empty placeholder with documented target structure

### Why this exists
The internal canon (`backend/app/schemas/canonical.py`) had reached
maturity but lived in a private monorepo, with a dual-stack legacy/canonical
overlap. Parallel to internal cleanup (Phase 1 of the canon migration —
see `../docs/canon-migration/`), this skeleton makes the public-spec
target visible from day one. Every Phase 2+ PR can now tier its work to
this directory.

### Out of scope for v0.0.0
- JSON Schema definitions for any artifact (Phase 2)
- Conformance test suite (Phase 2)
- ResponseAction / ConnectorCapability ABI implementation (Phase 2 — draft
  in `../docs/canon-migration/05-provider-abi.md`)
- Registry/modules story (Phase 3 — draft in
  `../docs/canon-migration/06-registry-thesis.md`)
- Multi-language SDKs (Python, Go, TS as separate packages — Phase 3)

[Unreleased]: ../../compare/warlog-spec-v0.0.0...HEAD
[0.0.0]: ../../releases/tag/warlog-spec-v0.0.0
