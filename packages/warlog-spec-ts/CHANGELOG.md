# Changelog

> **Version reset for first public release.** This package was
> internally developed up to `0.5.0` in lockstep with `warlog-spec-py`.
> For the first public npm artifact we reset to `0.1.0` to honestly
> signal pre-1.0 stability and match the Python package's release
> semantics. We do NOT use a `rc` suffix : v0.1 is an early
> experimental release, not a candidate for a v1.0 stable. Per semver,
> breaking changes between v0.1 and v0.2 are explicitly allowed. Both
> packages publish at the same version on the same day ; the cross-
> language byte-equivalence guarantee is preserved.

## [0.1.0] — 2026-05-20 — first public npm release

First artifact published to npm. Released in lockstep with
`warlog-spec` (Python) 0.1.0 from the public
`github.com/3noP/warlog-spec` repository.

Initial TypeScript reference implementation. Matches `warlog-spec-py`
0.1.0 in terms of types, factories, and audit-chain canonicalization.

### Added

- `@warlog/spec` npm package shell (ESM + CJS via tsup, strict
  TypeScript 5.x, Zod 3.x).
- `src/enums.ts` — 14 canonical workflow enums (Alert*, Case*,
  Entity*, IOCType, ComplianceScope, SelectorRepresentation,
  ProposalStepKind, IncidentPhase, ConfidenceBand, ArtifactReviewState).
- `src/provider-abi.ts` — 49-action `ResponseActionId` catalog +
  ConnectorCapability + descriptors + ResponseActionSpec/Result/Error
  + AuditActor (discriminated union HumanActor | AutomationActor) +
  AiAgentRef + AuditRow + AuditAttestation + SignedAuditRow +
  DecisionRef + TriggerSignalRef + DecisionArtifactType.
- `src/artifacts.ts` — 7 canonical artifacts (Mitre, Enrichment,
  Classification, Closure, CaseReturn, RiskArbitration,
  ApprovalDecision) + ArtifactEnvelope, Producer, Confidence,
  Citation primitives.
- `src/proposals.ts` — ProposalEnvelope + 4 proposals + payloads
  (Triage, NextStep, PlaybookCandidate, InvestigationSummary).
- *(Bundle projections — TriageBundle / InvestigationBundle /
  ResponseBundle / IncidentBundle — are intentionally out of scope of
  the open spec. They live in the Warlog backend as product-specific
  UI projections. The audit chain references no bundle ; the ABI
  references no bundle.)*
- `src/pack-manifest.ts` — PackManifest + sub-types.
- `src/audit-chain.ts` — canonicalize_v1 + HMAC primitives. Cross-
  language byte equivalence with Python's `warlog_spec.audit_chain`
  enforced by `tests/audit-chain.test.ts`.
- `src/conformance.ts` — 18 productible-type factories +
  `produceAll()` + `PRODUCERS` registry. Mirrors
  `warlog_spec.conformance` byte-for-byte (same pinned timestamps,
  same PII pseudonymization, same demo HMAC secret).
- 45 vitest tests : smoke (14) + audit-chain cross-lang (7) +
  conformance Level 2 (24).

### Added (reference connectors)

- `examples/crowdstrike-falcon-connector.ts` — 5 EDR actions via
  Falcon OAuth2 client_credentials + bearer-refresh, full
  `ConnectorAbiError` mapping for 401/403/404/409/422/429/5xx.
- `examples/okta-user-response-connector.ts` — 5 identity actions
  via Okta SSWS token + the GDPR pseudonymization gate (injected
  `resolveSubject` callback for hash → upn resolution).
- `tests/reference-connectors.test.ts` — 15 tests covering
  capability shape, auth failure mapping, dryRun side effects,
  full lifecycle happy path, PII gate behaviour with / without
  resolver, vendor-specific state_conflict detection.

### Conformance

- Level 1 (Read) : every produced output validates against the
  corresponding JSON Schema from `warlog-spec/schemas/` via Ajv.
- Level 2 (Write) : 18 productible types covered by `PRODUCERS`
  (bundles deliberately excluded — they are product-specific UI
  projections).
- Cross-language byte equivalence : `canonicalizeV1` output matches
  Python's `canonicalize_v1` byte-for-byte for the pinned audit row
  (see `packages/warlog-spec-py/tests/test_canonical_row_bytes.py`
  for the Python side — same `_GOLDEN` value, same sha256).
