---
RFC: 0001
Title: Trust layer — decision, signal, compliance, AI-agent attribution on AuditRow
Author: Warlog Spec maintainers
Status: Accepted, Implemented
Created: 2026-05-20
Requires:
Supersedes:
Superseded-By:
---

# RFC-0001 — Trust layer on AuditRow

## Abstract

`AuditRow` v1 logged *what* a connector did and *when*. It did not
log *why* (which decision authorized it), *from what* (which upstream
signal triggered it), *under which jurisdiction* (which regulated
perimeter it touched), or *by which agent* (when an autonomous LLM
issued the action). This RFC adds four fields to `AuditRow` and two
canonical artifact shapes (`RiskArbitration`, `ApprovalDecision`)
that close those four gaps, plus a public `SignedAuditRow` envelope
that makes any audit row independently verifiable.

## Motivation

The Warlog Spec article *"Substrate / Runtime / Trust Layer"* claims
the spec materializes the contract between human decisions and
machine execution. The pre-trust-layer `AuditRow` did not deliver
on that claim :

1. **No link to the decision.** A row that says
   `action_id=user.revoke_tokens, outcome=success` does not say which
   proposal, arbitration, or approval decision authorized the
   revocation. An auditor reconstructing the chain of intent has to
   triangulate via `idempotencyKey` and case timestamps.

2. **No link to the trigger.** Same shape : the row says the action
   ran, but not which OCSF event or alert triggered the analyst to
   request it. A malicious or buggy operator could fabricate a row
   for an action that had no upstream signal, and no auditor would
   detect it from the chain alone.

3. **No regulated-perimeter tag.** A regulated tenant (PCI DSS, DORA,
   NIS2, HDS) cannot filter audit history by jurisdiction without
   parsing free-form metadata. The audit query "show me everything
   that touched the PCI cardholder-data environment last quarter"
   requires scanning every row.

4. **No EU AI Act traceability when an agent acts.** When
   `actor.kind = "automation"`, the row only carries an opaque id
   (`agent:loop-001`). The EU AI Act and DORA require demonstrating
   *which model under which system prompt* issued the action, with
   a reasoning trace available for forensic review. The v1 row
   refuses that demand.

5. **No standalone verifiability.** An `AuditRow` exported alone is
   not verifiable — the HMAC signature and prev-row hash live in the
   internal storage layer (`SignedAuditRow` Python dataclass + DB
   columns), not on the published wire. A consumer who receives a
   single row through any channel other than the source DB cannot
   re-walk the chain.

The cost of these holes is high : a regulated SOC adopting Warlog
Spec cannot, today, satisfy DORA Art. 11 (audit trail) or AI Act
Art. 12 (record-keeping for high-risk AI systems) without
out-of-band correlation across multiple stores. This RFC closes
the gap inside the contract itself.

## Specification

### 1. Four new fields on `AuditRow`

| Field | Type | Required ? | Purpose |
|---|---|---|---|
| `decisionRef` | `DecisionRef` | **REQUIRED** | sha256-hashed pointer to the decision artifact (proposal, arbitration, approval decision) that authorized the action. |
| `triggerSignalRef` | `TriggerSignalRef` | **REQUIRED** | sha256-hashed pointer to the upstream signal (OCSF event, alert, IOC, playbook tick) that triggered the action. `kind=manual` allowed for analyst-initiated actions with no upstream signal. |
| `complianceScope` | `list[ComplianceScope]` | **REQUIRED** | Regulated perimeters this action touched. MAY be empty when no perimeter applies. Producers MUST emit explicitly. |
| `priorAuditId` | `str` | optional | When this row resolves a previous `pending_approval` row in the same execution, points to the audit_id of the pending row. |

`AuditActor` becomes a discriminated union `HumanActor | AutomationActor`.
The `AutomationActor` branch REQUIRES an embedded `AiAgentRef` :

```json
{
  "kind": "automation",
  "id": "agent:autonomous-soc:identity-containment-loop",
  "agent": {
    "model": "claude-opus-4-7",
    "modelVersion": "2026-04-15-build-c7d2e1",
    "systemPromptHash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "agentRunId": "run-7e2f1c44-9a8d-4c63-b0a1-3f5e8d7c9b21",
    "reasoningArtifactRef": "s3://warlog-reasoning/2026/05/run-7e2f1c44.json"
  }
}
```

`systemPromptHash` is the sha256 of the canonical system prompt bytes
(64 hex chars). An auditor with the prompt corpus re-hashes and
proves the agent ran under the policy it claims.

### 2. `ComplianceScope` enum

Nine values, extensible via additive minor RFCs :

```
nis2 | dora | pci_dss_v4 | sox | hds | secnumcloud | hipaa | gdpr | iso_27001
```

### 3. `RiskArbitration` artifact

Captures the signed, durable doctrinal decision that pre-authorizes
a class of actions on a scope until expiration. Schema :
`artifacts/risk-arbitration.json`. Surfaces the substrate the v1
contract was missing — Bob's tribal knowledge made into an
auditable, versioned, expirable artifact :

```json
{
  "envelope": { ... },
  "payload": {
    "authority": {
      "role": "ciso",
      "signerId": "user-rssi-mdupont",
      "signerName": "Marie Dupont"
    },
    "scope": [
      { "scopeKind": "asset_group", "selectorValue": "billing-prod-cluster" },
      { "scopeKind": "compliance_perimeter", "selectorValue": "pci_dss_v4_cde" }
    ],
    "acceptedRisks": [
      {
        "name": "lsass_memory_dump_during_maintenance",
        "description": "Authorized admin tool dumps LSASS for monthly credential-store integrity check."
      }
    ],
    "policyRef": {
      "policyKind": "playbook",
      "policyId": "playbook:lsass-maintenance-window-runbook",
      "version": "2026.04"
    },
    "validFrom": "2026-05-01T02:00:00Z",
    "validUntil": "2026-08-01T04:00:00Z",
    "justification": "Monthly credential-store integrity check signed off by CISO and DRO ..."
  }
}
```

### 4. `ApprovalDecision` artifact

Typed, signed record of an approval decision, distinct from the
request-side `ApprovalDescriptor`. Schema :
`artifacts/approval-decision.json`. Produced by the runtime
(`DbBackedApprovalGate` and/or `ApprovalService`) when an analyst
transitions a pending row to approved / denied. `requestRef` mirrors
the originating `ResponseActionSpec` so a consumer can reconstruct
the (request → decision → action) edge :

```json
{
  "envelope": { ... },
  "payload": {
    "requestRef": {
      "actionId": "user.revoke_tokens",
      "subjectKind": "identity",
      "subjectValue": "<sha256_salted hash>",
      "idempotencyKey": "case:CASE-2026-0042:user.revoke_tokens:..."
    },
    "decisionMakerKind": "human",
    "decisionMakerId": "user-senior-bclaudel",
    "decision": "approved",
    "decidedAt": "2026-05-06T10:20:54.812Z",
    "basisRef": {
      "policyKind": "playbook",
      "policyId": "playbook:token-revocation-on-confirmed-takeover",
      "version": "2026.03"
    },
    "rationale": "Confirmed account takeover. Tier-2 containment per playbook."
  }
}
```

### 5. `SignedAuditRow` envelope

Public, transportable, verifiable wrapper around `AuditRow`. Schema :
`provider-abi/signed-audit-row.json`. Pattern : JWS-like. The
payload is the `AuditRow` ; `attestation` carries the HMAC signature
and prev-row hash :

```json
{
  "specVersion": "1.0",
  "payload": { /* AuditRow */ },
  "attestation": {
    "prevRowHash": "<64-hex HMAC of the prior row>",
    "signatureValue": "<HMAC-SHA256 over (prev_row_hash || canonical_bytes)>",
    "algorithm": "HMAC-SHA256",
    "canonicalizationFormat": "v1",
    "keyId": "tenant:T-001:secret:v3"
  }
}
```

A consumer with the matching tenant secret recomputes the HMAC from
`canonicalize_v1(payload)` and confirms `signatureValue`. The
canonical-bytes form is NOT carried inline — a consumer recomputes
it from `payload`. This decouples on-the-wire size from chain
depth.

### 6. GDPR pseudonymization gate

`ResponseSubject` gains `selectorRepresentation` (enum
`raw | sha256 | sha256_salted`) and `selectorKeyId`. The runtime
MUST refuse to sign a row whose action is in family `identity`,
`email`, or `iam` and whose `selectorRepresentation` is not
`sha256_salted` — error returned to the connector is
`POLICY / warlog.gdpr.pii_required`.

Salt rotation tenant-side = de-facto erasure of pre-rotation rows
without mutating the append-only chain.

### 7. `DecisionArtifactType` → schema mapping

Published as `provider-abi/decision-artifact-type-mapping.json`.
Bidirectional completeness enforced by conformance test
(`test_decision_artifact_type_mapping_is_complete_and_consistent`) :
every enum value MUST have a corresponding schema, every mapped
schema MUST exist on disk.

## Design rationale

**Why a cryptographic chain rather than a database constraint ?**
Database constraints can be bypassed by an operator with write
access to the table. The HMAC-chained `SignedAuditRow` is verifiable
by an auditor who never had access to the live database — they
hold a copy of the secret (or its key id resolves to an external
key custodian) and re-walk the chain end-to-end. The chain is the
ground truth ; the DB is one mirror.

**Why a separate `ApprovalDecision` artifact rather than just
fields on `AuditRow` ?** Approval decisions are referenced from
multiple audit rows (the approval phase row, the apply phase row,
the verify phase row, future actions in the same execution that
re-validate the prior approval). Inlining the decision metadata
into each row would force re-serialization and complicate the
content-hash invariant. The artifact lives once, every row
references its hash.

**Why pseudonymize PII selectors rather than encrypt them ?**
Encryption requires key management at audit-replay time —
auditors need the keys to read the rows. Pseudonymization with a
rotatable salt means the keys are only needed *during the
retention window* ; rotation makes pre-rotation rows
effectively non-reversible (de-facto erasure), satisfying GDPR
right-to-erasure without mutating the chain. The audit chain
remains intact ; the identity behind the hash dissolves on
schedule.

**Why `ComplianceScope` as an enum rather than free-form
labels ?** Free-form labels drift. NIS2 vs nis2 vs NIS-2 vs
"NIS Directive 2" all mean the same thing to a human and
different things to a SQL filter. The enum forces a canonical
spelling at producer time ; new frameworks land via additive
minor RFCs.

**Why `AuditActor` as a discriminated union rather than a flag ?**
Pydantic v2 + Annotated Union with `discriminator="kind"` produces
clean JSON Schema `oneOf` with a discriminator property. Consumers
get type-narrowing for free, JSON Schema validators reject
malformed actor shapes at parse time, and the AI-Act fields can
be REQUIRED specifically when `kind=automation` without
contaminating the human actor branch.

## Alternatives considered

### A. Decision/signal references via `idempotencyKey` only

Don't add fields ; encode the decision and trigger refs inside a
structured `idempotencyKey` string. Pros : zero schema change.
Cons : (1) opaque to schema validators ; (2) no content-hash
verifiability — an operator can rewrite the key without
detection ; (3) breaks the doctrine that the contract should
make linkage explicit, not implicit by string convention.
Rejected for the same reasons we don't encode tenant ids in
filenames.

### B. AI Act fields as a top-level optional field rather than
inside `AutomationActor`

Pros : simpler shape (no discriminated union). Cons : (1)
allowed combinations grow ambiguous ("can a human actor have
an aiAgent ?", "what does an empty aiAgent for a human mean ?")
; (2) the AI Act REQUIRES traceability for autonomous decisions,
not optional, so leaving the field absent for `kind=automation`
should be a contract violation, not just a missing best practice.
The discriminated union encodes the obligation in the type
system.

### C. Per-row encrypted PII rather than hash + rotatable salt

Pros : reversible identification within retention. Cons : (1) key
custody at audit-replay time is operationally expensive ; (2)
mandatory key destruction at end of retention is hard to prove ;
(3) defeats the audit chain's "minimal long-lived secret"
discipline. Pseudonymization wins on operational simplicity and
de-facto erasure guarantees.

### D. `SignedAuditRow` not published, kept internal

Pros : smaller public surface. Cons : (1) defeats the article's
"anyone can verify" thesis ; (2) third-party adopters cannot
build standalone verifiers ; (3) is incompatible with the spec's
own claim of being a portable contract. Publishing the envelope
is essential to credibility.

## Backward compatibility

The spec is **pre-public** at the time of this RFC. The breaking
nature of these changes lands in-place on ABI v1.0 rather than as a
v2.0 bump — there are no external adopters pinned to a version yet.
This decision is documented in [`feedback_no_version_bump_prepublic`](../../memory/feedback_no_version_bump_prepublic.md)
and ratified in this RFC.

Once an external adopter ratifies this RFC by claiming Level 2
conformance in `COMPAT.md`, subsequent breaking changes MUST follow
the version bump policy in `VERSIONING.md`.

### Migration notes for the reference implementations

- `warlog-spec-py` factories : extended to produce all 22
  productible types, including the new `SignedAuditRow`, with PII
  examples pseudonymized.
- `warlog/backend` runtime : `AbiRunner.execute()` now takes an
  `ExecutionContext` (actor + decision_ref + trigger_signal_ref +
  compliance_scope) instead of just `actor`. Connectors are
  unaffected (the runner is what builds the row).
- DB migration `20260520_0100` adds promoted columns to
  `connector_audit_chain` ; `20260520_0200` adds the
  `canonical_decision_artifacts` table.

## Reference implementation

- `warlog-spec-py` : schemas + Pydantic models in
  `packages/warlog-spec-py/src/warlog_spec/` (provider_abi.py,
  artifacts.py, proposals.py).
- `@warlog/spec` : same surface in TypeScript via Zod, byte-equivalent
  canonicalization (see `packages/warlog-spec-ts/`).
- `warlog/backend` : `AbiRunner` (with `ExecutionContext` +
  PII-pseudonymization gate), `DbBackedApprovalGate` (with
  lazy artifact emission), `ApprovalService` (with synchronous
  artifact emission), `CanonicalDecisionArtifactStore`.
- Conformance : 18 productible canonical-spec types covered by
  `warlog_spec.conformance.produce_all()`. Level 1 + Level 2 green
  against the canonical examples and the reference fixtures. UI
  projection shapes (`TriageBundle`, `InvestigationBundle`,
  `ResponseBundle`, `IncidentBundle`) are deliberately out of scope of
  the open spec — they live in the backend as product-specific
  projections.

## Open questions

- **External RiskArbitration ingest API.** Today `RiskArbitration`
  can be persisted via the store but there is no first-class
  ingest endpoint for a RSSI signing console. Tracked as a future
  RFC.
- **AiAgentRef extensions.** The current shape covers single-model
  agents. Multi-agent / tool-using compositions (sub-agent chains,
  retrieval-augmented decisions) may need an additional field for
  the sub-agent tree. Tracked as a future RFC.
- **Outbound STIX projection of CaseReturnSummary.** A future RFC
  may add a `case_return_summary → STIX Note` projection so
  threat-intel partners receive a portable closure record.
- **Beyond HMAC-SHA256.** `AuditAttestation.algorithm` is a
  `Literal["HMAC-SHA256"]` today. An additive RFC will extend it
  to Ed25519 / RSASSA-PSS for organizations that require
  asymmetric signing (signer ≠ verifier custody model).

## References

- `warlog-spec/docs/ECOSYSTEM-MAPPING.md` — how the trust-layer
  fields interact with OCSF, STIX, OpenC2, CACAO, OSCAL.
- `warlog-spec/CHANGELOG.md` — `[Unreleased]` section documents
  the change in operator-facing language.
- `feedback_no_version_bump_prepublic.md` (internal) — rationale
  for landing breaking changes in-place pre-publication.
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) Art. 12 — record-keeping requirements for high-risk AI.
- [DORA](https://eur-lex.europa.eu/eli/reg/2022/2554/oj) Art. 11 — ICT-related incidents response and recovery.
- [NIS2](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) — annex on incident reporting.
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/) — Requirement 10 (logging and monitoring).
- [GDPR](https://eur-lex.europa.eu/eli/reg/2016/679/oj) Art. 17 — right to erasure.
