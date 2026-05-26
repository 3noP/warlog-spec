---
RFC: NNNN
Title: <short noun phrase>
Author: <name> <<email@example.org>>
Status: Draft
Created: YYYY-MM-DD
Requires:
Supersedes:
Superseded-By:
---

# RFC-NNNN — <title>

## Abstract

Two or three sentences a non-implementer can read. What does this RFC
introduce, why, and what's the visible effect on a consumer of the
spec ?

## Motivation

What hole does this RFC fill ? Describe the world without this RFC —
what breaks, what's awkward, what's impossible. A motivation that
just says "we wanted X" is too thin ; ground it in an operator's pain
or an adopter's blocker.

## Specification

The normative content. Use MUST / SHOULD / MAY per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

When introducing schema changes, embed concrete JSON examples and
reference the schema relpath (e.g. `provider-abi/audit-row.json`).
Producers, consumers, and the conformance runner all read this
section as the source of truth.

## Design rationale

Why this design rather than the alternatives ? Be explicit about the
trade-offs you accept. A design rationale that says "this is the
cleanest design" is not a rationale — name the constraints that
make this design correct.

## Alternatives considered

At least one. For each : describe it, then explain why it was
rejected. The point is to make the absence of those alternatives in
the final design legible to a future reader who wasn't in the
discussion.

## Backward compatibility

What breaks ? Who needs to migrate ? What's the migration path ?

- For **additive** changes (new optional field, new enum value),
  state "fully backward compatible" and explain how old consumers
  handle the new content.
- For **breaking** changes, document the version bump (or, pre-v1,
  the in-place breakage) and the migration steps.

## Reference implementation

Links to PR(s) that implement this RFC :

- `warlog-spec-py` : [PR #...]()
- `warlog/backend` : [PR #...]()

The RFC moves to `Implemented` status once the reference
implementation ships.

## Open questions

Sub-decisions that this RFC deliberately defers. Each one SHOULD
have a follow-up RFC number reserved (or a clear note that no
follow-up is planned).

## References

- Related ecosystem standards : [OCSF](https://schema.ocsf.io/),
  [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html),
  [OpenC2](https://docs.oasis-open.org/openc2/oc2ls/v1.0/oc2ls-v1.0.html),
  [CACAO](https://www.oasis-open.org/committees/cacao/),
  [OSCAL](https://pages.nist.gov/OSCAL/).
- `warlog-spec/docs/ECOSYSTEM-MAPPING.md`
- `warlog-spec/CHANGELOG.md`
- Previous discussions : [issue #...]() / [PR #...]()
