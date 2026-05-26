# Contributing to Warlog Spec

> **Status:** first public release (v0.1.0 — experimental, pre-v1.0). CLA tooling
> and RFC automation will land progressively over subsequent v0.x
> releases. The process below describes the steady-state target ;
> until tooling catches up, file an issue and reference it from your PR.

## What kinds of contributions are welcome

- **Schema changes** — adding fields, enum values, artifact types, or
  refining existing ones. See `VERSIONING.md` for additive vs. breaking
  semantics.
- **Examples** — canonical JSON examples for an existing schema. Anyone
  can submit; they round-trip-validate or they don't.
- **OCSF / STIX / Sigma / OpenC2 mapping refinements** — see `COMPAT.md`.
- **Conformance tests** — once the test harness exists in `tests/conformance/`.
- **Documentation** — clarifications to `README.md`, `VERSIONING.md`,
  `GOVERNANCE.md`, or the spec prose.
- **Reference implementation feedback** — file an issue describing how
  the spec is or isn't matching what you tried to build.

## Out of scope here (open elsewhere)

- Bugs, features, or roadmap discussions for the Warlog **product** —
  open in the parent `warlog` repository.
- Pack content (detection rules, playbooks, KB articles) — open in the
  registry / packs repository (planned post-v1.0).
- Connector implementation code — open in the connector repository for
  the vendor in question.

## How a change lands

1. **Open an RFC issue** using the `RFC` template (see
   `rfcs/template.md`). Describe the problem, the proposed schema
   delta, and at least one example.
2. **Discussion** on the issue. Implementation experiments are welcome
   *before* the RFC is merged — they often inform the final design.
3. **Open a PR** referencing the RFC. The PR MUST include:
   - The schema diff (`schemas/`)
   - At least one example (`examples/`) that validates against the new schema
   - A `CHANGELOG.md` entry under `[Unreleased]`
   - For breaking changes (MAJOR per `VERSIONING.md`): a migration note
4. **Review thresholds**:
   - PATCH (doc / clarification, no schema diff): 1 maintainer approval
   - MINOR (additive schema change): 2 maintainer approvals
   - MAJOR (breaking schema change): 3 maintainer approvals + 14-day public
     review window
5. **Merge** to `main`. MINOR/MAJOR changes also tag a release per
   `VERSIONING.md` cadence.

## Contributor License Agreement

Until the spec leaves bootstrap (`v1.0.0`), all non-trivial contributions
require signing the Warlog CLA. This is the same CLA as the parent project
and is required so that the maintainers can:

- Re-license the spec under different terms if a foundation move (CNCF /
  LF Cybersecurity / OASIS) requires it.
- Defend the spec against patent assertions on contributors' behalf.

The CLA is **not** a copyright assignment. You retain copyright on your
contributions. The CLA grants the project a perpetual license to use them.

The CLA bot will comment on your first PR with a one-time signing link.

## Code of conduct

This project follows the code of conduct in `CODE_OF_CONDUCT.md`.
Disagreement on schema decisions is welcome and necessary; personal
attacks are not. The maintainers will moderate as needed.

## Where to start

- File an issue with the `proposal/` or `question/` label.
- Comment on an open RFC issue.
- Submit an example for an existing schema (low-friction first contribution).
- Pilot an implementation against the draft spec and report what's missing.

## Maintainer contact

For sensitive matters (security disclosures on the spec design,
trademark concerns, governance escalation), contact the parent project's
maintainers privately. For security reports, see `SECURITY.md`.
