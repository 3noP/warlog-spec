# Warlog Spec — Request For Comments (RFCs)

How changes to the spec are proposed, debated, and ratified. Style
inspired by Python PEPs and IETF RFCs, kept lighter to match the spec's
bootstrap phase.

## Numbering

- `0001` to `0099` reserved for foundational design decisions
  (trust layer, action catalog policy, conformance harness).
- `0100+` for incremental additions (new action ids, new artifact
  shapes, new compliance scopes).
- Filename : `<NNNN>-<short-kebab-slug>.md`. Once a number is
  assigned, it is permanent — even if the RFC is later Rejected
  or Withdrawn.

## Status flow

```
Draft ──► Last Call ──► Accepted ──► Implemented
                  └──► Rejected
                  └──► Withdrawn
                  └──► Superseded
```

- **Draft** : author actively iterating. PR open against `rfcs/` ;
  comments collected in the PR thread.
- **Last Call** : the author + maintainers consider the document
  ready. A 14-day public comment window opens (28 days for any RFC
  that touches `ABI_VERSION` or canonicalization). The PR title is
  prefixed with `[Last Call]` and announced in the project's
  discussions channel.
- **Accepted** : maintainer consensus reached, no blocking concerns
  surfaced during Last Call. Merged into `main`. Implementations
  start.
- **Implemented** : at least the reference implementation
  (`warlog-spec-py` + `warlog/backend`) has shipped the RFC's
  changes. The RFC document's frontmatter is updated with the
  implementation reference.
- **Rejected** : the RFC was discussed in Last Call (or earlier)
  and dropped. The document remains as historical context with
  a note explaining why.
- **Withdrawn** : the author withdrew before consensus was
  reached.
- **Superseded** : a later RFC obsoletes this one. The frontmatter
  `Superseded-By` points to the replacement.

Status transitions are recorded in the document's frontmatter and
in `CHANGELOG.md` of the spec.

## Approval threshold

| RFC type | Maintainer approvals | Last Call window |
|---|---|---|
| **Editorial** (typo, clarification, no schema diff) | 1 | none |
| **Additive minor** (new field optional, new enum value, new artifact type) | 2 | 14 days |
| **Breaking / major** (field removal, ABI_VERSION bump, canonicalization change) | 3 | 28 days |

Maintainers are listed in `GOVERNANCE.md`. External contributors
need a CLA signed (see `CONTRIBUTING.md`) before their RFC can be
merged.

## Document structure

Every RFC uses `template.md` as a starting point. Required sections :

1. **Frontmatter** : RFC number, title, author, status, created,
   requires, supersedes.
2. **Abstract** — 2-3 sentences readable by a non-implementer.
3. **Motivation** — what hole does this fill ? What does the
   ecosystem look like without this RFC ?
4. **Specification** — the normative content. Use MUST / SHOULD /
   MAY per RFC 2119. Embed JSON examples when shapes change.
5. **Design rationale** — why this design vs the alternatives ?
6. **Alternatives considered** — list at least one alternative
   and why it was rejected. An RFC with zero alternatives looks
   like a foregone conclusion to reviewers ; force the comparison.
7. **Backward compatibility** — what breaks ? Migration path ?
   For pre-v1 RFCs : declare that breaking is acceptable but
   document the breakage.
8. **Reference implementation** — link to the PR(s) in
   `warlog-spec-py` and `warlog/backend` that implement this RFC.
9. **Open questions** — known unresolved sub-decisions. Tracked
   for follow-up RFCs.
10. **References** — links to ecosystem standards, prior art,
    relevant issues.

## How to propose

1. Fork the repo, copy `rfcs/template.md` to
   `rfcs/<NNNN>-<slug>.md` using the next available number.
   Check open PRs for in-flight numbers to avoid collisions.
2. Fill in the sections. A `Draft` status is fine for the initial
   PR — iterate.
3. Open a PR titled `RFC-<NNNN>: <title>`. Tag at least one
   maintainer for review.
4. Iterate based on PR comments. When the discussion settles,
   ask a maintainer to flip the status to `Last Call`.
5. After the comment window closes and the threshold is met,
   a maintainer merges the PR (status `Accepted`).

## RFC index

| Number | Title | Status |
|---|---|---|
| [0001](0001-trust-layer.md) | Trust layer — decision / signal / compliance / AI-agent attribution on AuditRow | Accepted, Implemented |
| [0002](0002-ai-agent-ref-extensions.md) | AiAgentRef extensions for multi-agent and tool-using compositions | Accepted, Implemented |
| [0003](0003-stix-projection.md) | Outbound STIX 2.1 projection of CaseReturnSummary | Accepted, Implemented |
| [0004](0004-asymmetric-signatures.md) | Asymmetric signatures (Ed25519, RSASSA-PSS) for AuditAttestation | Accepted, Schema Implemented |
