# Governance

> **Status:** bootstrap. Current model is BDFL with a deliberate path to
> open up. The path matters more than the current state — it tells
> potential adopters that lock-in to a single vendor isn't the long-term
> intent.

## Current model — BDFL (Benevolent Dictator For Life)

While Warlog Spec is below `v1.0.0`, final decision authority rests with
the project founder (the parent Warlog project's founder). This is the
same model Sigma had during its early years (Florian Roth) and the same
HashiCorp had with Terraform pre-foundation moves.

**Why BDFL during bootstrap**:
- Schema decisions move faster.
- The spec is being extracted from a working product; the founder has
  the most context on which trade-offs are load-bearing.
- External contributors can engage without a heavy process burden.

**What BDFL means in practice**:
- The founder reviews and merges all schema-affecting PRs.
- Disagreements are resolved by discussion, then by the founder if no
  consensus emerges.
- Decisions are documented in the relevant RFC issue + CHANGELOG.

## Path to community governance

The intent is to **dilute BDFL authority** as adoption grows. The
milestones below are concrete and public so adopters can verify progress.

### v1.0.0 — Technical Committee (target: 2027)

A 5–7 person Technical Committee replaces BDFL for schema decisions:

- 1 seat: parent project maintainer
- 1–2 seats: practitioner / SOC operator (someone running a SOC, not a vendor)
- 1–2 seats: MSSP representative
- 1 seat: tier-2 SIEM or workflow-engine vendor that has shipped a conformant implementation
- 1 seat: open-source ecosystem contributor (TheHive / OpenCTI / Wazuh / similar project)

The Committee operates by consensus where possible and by majority vote
on contested questions. The parent project maintainer holds **veto only
on items that would force an AGPL3 licensing conflict** with the parent
runtime — not on schema design itself.

### v1.x — Foundation move (target: 18–24 months after v1.0)

Once external adoption is demonstrable (≥10 third-party conformant
implementations, ≥3 production deployments outside the parent project),
the spec moves to a neutral foundation. Candidate hosts:

- **CNCF Sandbox** — lowest friction, technical focus, accepts emerging
  standards.
- **Linux Foundation Cybersecurity** — broader Sec/SOC framing, parallel
  to OCSF.
- **OASIS** — heavyweight, formal, slower but maximum standards
  legitimacy. Same home as STIX 2.1.

The choice is left to the Technical Committee at the time of the move.

## What governance does NOT cover

- **Pack content** (detection rules, playbooks, KB articles) — those have
  their own publisher-level governance per `06-registry-thesis.md` (in
  the parent repo's docs).
- **Reference implementation roadmap** — that's the parent project's
  call.
- **Trademark "Warlog"** — owned by the parent project's commercial
  entity. The foundation move (when it happens) negotiates a trademark
  policy that allows ecosystem use without dilution.

## Decision log

Significant governance changes are recorded as `gov/GOV-XXXX-*.md` files
(once that lane exists post-v1.0). Pre-foundation decisions are documented
in the relevant RFC issue thread and surfaced in `CHANGELOG.md`.

## How to influence governance

1. **Ship a conformant implementation.** Voting weight comes from
   demonstrated commitment.
2. **Engage on RFCs.** The Committee is selected partly from people who
   have engaged constructively over time.
3. **Run a public registry mirror or curated pack collection.** Visible
   ecosystem contribution is the fastest path to a Committee seat.

## Conflict resolution

For schema design conflicts: discussion → BDFL decision (current) →
Technical Committee vote (post v1.0).

For Code of Conduct violations: see `CONTRIBUTING.md`.

For governance escalation (e.g. claim that a maintainer abused authority):
parent project's `SECURITY.md` contact path. Independent third-party
review is committed to once the Technical Committee exists.
