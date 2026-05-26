---
RFC: 0003
Title: Outbound STIX 2.1 projection of CaseReturnSummary
Author: Warlog Spec maintainers
Status: Accepted, Implemented
Created: 2026-05-20
Requires: 0001
Supersedes:
Superseded-By:
---

# RFC-0003 — Outbound STIX 2.1 projection of CaseReturnSummary

## Abstract

`warlog-spec` consumes STIX 2.1 inbound (indicators → IOCs, reports
→ KB articles) but produces no STIX outbound — closure summaries
stay inside the tenant. This RFC defines a one-way projection from
`CaseReturnSummary` to a STIX 2.1 `Note` object so a tenant can
share a portable closure record with a threat-intel partner without
re-implementing the shape per consumer. Optionally projects
`EnrichmentAssessment.matchedIocs` to STIX `Indicator` objects.

## Motivation

The article positions warlog-spec as a layer **above** the existing
standards : we consume, translate, embed. The STIX entry in
`docs/ECOSYSTEM-MAPPING.md` already documents inbound : indicators →
`ExtractedIOC`, reports → KB, courses-of-action → playbook ids.

But outbound is missing. A `CaseReturnSummary` is the artifact a
case produces on closure : final verdict, root cause, lessons
learned, linked alerts. Today that artifact lives in
`canonical_decision_artifacts` and a tenant who wants to share
their closure with a threat-intel partner has to translate to STIX
by hand — which means every tenant invents its own translation and
the goal of interop breaks.

A canonical, opinionated, **one-way** projection (warlog →
STIX) closes the gap. STIX 2.1 already has the right object for
this : a `Note` ties prose context to a set of `object_refs`. We
emit a Note whose `content` carries the closure summary, whose
`object_refs` carry the linked alerts (modeled as STIX `Incident`
ids), and whose timestamps and identifier follow the STIX 2.1
contract.

Inbound STIX → warlog is **not in scope** for this RFC. It exists
as a follow-up RFC slot.

## Specification

### Projection contract

Given a `CaseReturnSummary` instance, the projection produces a
STIX 2.1 [Note](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_gudodcg1sbb9)
object with these fields :

| STIX field | Source |
|---|---|
| `type` | constant `"note"` |
| `spec_version` | constant `"2.1"` |
| `id` | `note--<uuid5>` where the uuid5 namespace is fixed (see below) and the name is the CaseReturnSummary's `caseId` |
| `created` | RFC 3339 timestamp from `CaseReturnSummary.generatedAt` |
| `modified` | same as `created` (Notes are immutable in our projection) |
| `created_by_ref` | producer identity, projected to an `identity--<uuid5>` ref derived from the tenant id (operator-supplied) |
| `abstract` | string `f"Closure of {caseNumber} — verdict={finalVerdict.upper()}"` (capped at 200 chars) |
| `content` | structured markdown summarizing : final verdict + category + severity, root cause, outcome summary, lessons learned. Capped at 65535 chars (STIX 2.1 max). |
| `authors` | `[<created_by_ref display name or "warlog-spec">]` |
| `object_refs` | for each linked alert id, a deterministic `incident--<uuid5>` ref (alert id used as uuid5 name) — STIX 2.1 has no first-class alert object, Incident is the closest. |
| `external_references[0]` | `{ source_name: "warlog-spec", external_id: caseId, url: <optional tenant-supplied case URL> }` |
| `labels` | `["closure", finalCategory.value]` |
| `confidence` | integer 0-100, derived from `CaseReturnSummary.confidence.band` (low=25, medium=60, high=85, unknown=0) |

The projection is **lossless on the fields it covers** but **lossy
on the rest** : `linkedAlertIds[]` becomes `object_refs[]` (alert
identity is preserved via uuid5 derivation, but the alert payload
is not embedded — a STIX consumer fetches it separately).

### UUID5 namespace

To make the projection deterministic (same input → same STIX ids),
we fix a namespace OID for the spec :

```
6b9d2b2b-7e1a-5c4f-9d3e-warlog-spec-stix-projection
```

Concretely : `uuid.uuid5(NAMESPACE_OID, "warlog-spec:stix:" + identifier)`.

This guarantees that two tenants projecting the same
`CaseReturnSummary` produce the same STIX ids — useful for
deduplication on the consumer side when the same closure is shared
with multiple partners.

### Optional : Indicator projection

When the source case has `EnrichmentAssessment.payload.matchedIocs`
populated, the projector MAY emit one STIX `Indicator` object per
IOC, with :

- `type: "indicator"`, `spec_version: "2.1"`
- `id: "indicator--<uuid5>"` derived from the IOC value
- `pattern_type: "stix"`, `pattern: "[<stix pattern matching the ioc>]"`
- `valid_from: <ExtractedIOC.firstSeen>`
- `confidence`, `labels`, `created_by_ref` derived as for the Note

Indicators are emitted alongside the Note in a STIX
[Bundle](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_gms872kuzdmg).
The Note's `object_refs[]` MAY include the indicator ids.

## Design rationale

**Why a Note rather than an Incident extension ?** STIX `Incident`
exists but is described as "stub" in 2.1 — its content shape is
TBD by the OASIS TC and varies by vendor profile. `Note` is fully
specified, immutable, has the right `content` + `object_refs`
semantics, and survives every STIX consumer that parses 2.1
verbatim. We pick the stable shape.

**Why deterministic uuid5 ids ?** Cross-tenant deduplication. Two
MSSPs sharing intel with the same partner about the same case
produce the same STIX id, so the partner's STIX store can collapse
on insert. Reduces noise.

**Why outbound only, not bidirectional ?** Inbound STIX (consuming
indicators / reports) already works for warlog via the existing
threat-intel adapters that produce `ExtractedIOC` and KB articles —
no new shape is needed. Outbound is the actual hole.

**Why not project all CanonicalArtifact types ?** Most of them
don't have natural STIX counterparts. `RiskArbitration` would
project to an OSCAL profile reference, not a STIX object.
`ApprovalDecision` is a runtime decision, not threat intel. Only
`CaseReturnSummary` (closure context worth sharing) has a clean
STIX target. Future RFCs can add more projections case-by-case.

## Alternatives considered

### A. Project to STIX `Report` instead of `Note`

Pros : Report carries a name + description, closer to how a SOC
talks about closures. Cons : (1) Report is intended for finished
"intel reports" with a publication semantic, whereas a closure
summary is an internal operational artifact ; (2) Report requires
non-empty `published` and `object_refs`, and we may not always
have meaningful refs ; (3) Notes are more permissive (zero or more
refs). Note wins on operational fit.

### B. Bidirectional projection in one RFC

Pros : symmetry. Cons : (1) doubles the scope without doubling the
value (we don't have a hole on the inbound side) ; (2) the
inbound work needs a STIX adapter for each STIX object type, not
just `Note`/`Indicator`. Defer to a follow-up RFC.

### C. Custom STIX extension (`x-warlog-closure`)

Pros : maximum fidelity — every field of `CaseReturnSummary` maps
to a custom STIX property. Cons : (1) defeats the interop goal —
no STIX consumer reads our custom extension ; (2) STIX 2.1 already
has a portable mechanism (Note + external_references) for this
exact use case. Custom extension is for content STIX
fundamentally lacks, which is not the case here.

### D. JSON-LD / OSCAL instead of STIX

Pros : OSCAL is the natural format for control-aware closure
records. Cons : OSCAL targets controls assessment, not threat-
intel sharing. A `CaseReturnSummary` is operational closure, more
threat-intel-flavoured than compliance-flavoured. We pick the
right OASIS spec for the audience.

## Backward compatibility

Fully additive. New module `warlog_spec.stix_projection` is opt-in
— consumers MUST import and call it explicitly. No change to any
existing artifact, schema, or endpoint.

## Reference implementation

- `warlog-spec-py` : new module `warlog_spec.stix_projection` with
  `case_return_to_stix_note(case_return: CaseReturnSummary,
  *, tenant_id: str, case_url: str | None = None) -> dict`. Returns
  the STIX Note as a `dict` ready for JSON serialization.
- `@warlog/spec` : equivalent `caseReturnToStixNote()` function in
  `packages/warlog-spec-ts/src/stix-projection.ts`.
- Tests : `packages/warlog-spec-py/tests/test_stix_projection.py`
  validates the shape against STIX 2.1 required fields and
  deterministic id derivation. TS equivalent in
  `packages/warlog-spec-ts/tests/stix-projection.test.ts`.

## Open questions

- **Inbound STIX projection.** Symmetrical work for parsing STIX
  Notes / Reports / Incidents back into Warlog artifacts. Tracked
  as a future RFC.
- **STIX Bundle assembly.** When projecting a case with N matched
  IOCs, the projector currently emits Note + N Indicators as
  separate dicts. A helper to assemble them into a STIX Bundle
  with deterministic Bundle id is straightforward and may land in
  the same module as the projection grows.
- **TLP marking.** STIX supports
  [Traffic Light Protocol](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_yd3ar14ekwrs)
  via marking definitions. Today the projection does not emit
  TLP markings — a follow-up RFC may add a tenant-default TLP
  level and per-case override.

## References

- [STIX 2.1 Note object](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_gudodcg1sbb9)
- [STIX 2.1 Indicator object](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_muftrcpnf89v)
- [STIX 2.1 Bundle](https://docs.oasis-open.org/cti/stix/v2.1/cs02/stix-v2.1-cs02.html#_gms872kuzdmg)
- `warlog-spec/docs/ECOSYSTEM-MAPPING.md` (STIX 2.1 row)
- RFC-0001 — defines `CaseReturnSummary` shape.
