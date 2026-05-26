# Versioning policy

## Semver, applied to a schema spec

Warlog Spec follows **semver 2.0** with explicit semantics for schema changes:

- **MAJOR** (`X.0.0`) — breaking change. Any of:
  - Removing a field
  - Removing an enum value
  - Renaming a field or enum value (without alias)
  - Tightening a constraint (e.g. `optional` → `required`, widening bound, narrowing pattern)
  - Removing or restructuring an artifact / proposal type
  - Changing the wire format of an envelope
- **MINOR** (`x.Y.0`) — additive, backward-compatible. Any of:
  - Adding a new optional field
  - Adding a new enum value
  - Adding a new artifact / proposal type
  - Adding a new ResponseAction or ConnectorCapability
  - Adding a new normalize alias for legacy producer values
- **PATCH** (`x.y.Z`) — clarification only. No schema diff. Doc, examples,
  validation messages.

## Bootstrap phase (v0.x)

While the spec is below `v1.0.0`, **breaking changes are permitted** between
minor versions. Producers/consumers MUST pin to a minor version. The first
`v1.0.0` release commits to permanent stability.

Goal: reach `v1.0.0` after at least 3 external adopters have implemented
against the spec and at least 6 months of post-bootstrap iteration.

## Deprecation policy

- A field or enum value can be **deprecated** in any minor release.
- A deprecated element MUST remain functional for at least **2 minor
  versions** before removal in a major bump.
- Deprecation is signaled in `CHANGELOG.md` and via `// DEPRECATED:` annotations
  in JSON Schema `description`.

## Spec version vs. artifact version

Each artifact carries its own `*_version` field independently of the global
spec version:

```jsonc
{
  "proposal_type": "next_step",
  "proposal_version": "v1",   // artifact semver — independent
  // ...
}
```

A consumer SHOULD accept any artifact whose `*_version` major matches the
producer's declared spec version major. Cross-major artifact translation is
the producer's responsibility (or the registry's, when adapter packs land).

## Compatibility matrix

`COMPAT.md` tracks which provider/library implementations claim conformance
to which spec versions. Conformance = passes the conformance test suite for
that version, including the valid examples and invalid corpus under
`tests/conformance/`.

## Test target doctrine

The conformance test target is **"100% of public versioned spec surfaces"**,
not "100% of internal enums". Concretely:

- Every enum value in the spec → has at least one round-trip example in
  `examples/`.
- Every artifact / proposal type → has a canonical example in
  `examples/` (18 productible types at `v0.1.0`).
- Every released version → has a snapshot of valid examples and invalid
  fixtures that MUST be rejected by schemas.

UI-projection shapes (the per-product bundle types describing
triage / investigation / response / incident screens) are deliberately
out of scope of the open spec — they live in the operator's runtime,
not in `warlog_spec`. See `packages/warlog-spec-py/CHANGELOG.md`
"Out of scope" section for the doctrine.

## Branch / release model

- `main` — current draft. Not authoritative.
- `release/vX.Y` — frozen branches for each minor release. Patches
  cherry-picked.
- Tags `vX.Y.Z` on `release/vX.Y`.
- Long-lived branches: only LTS minors (declared explicitly).

## Contributing changes to the spec

1. Open an RFC issue (template: `rfcs/RFC-XXXX-*.md` once that lane exists).
2. Discussion on the issue. Implementations welcome before merge — they
   inform the spec.
3. PR against `main` referencing the RFC.
4. Two maintainer approvals required for additive minor; three + a 14-day
   public review for any major.
5. Examples + CHANGELOG entry mandatory before merge.
