# Warlog Spec

> **The canonical workflow contract for Security Operations.**
>
> *OCSF answers "what happened?". Warlog Spec answers "what do we do about it?".*

**Status** : ABI `v1.0`, spec packages at `v0.1.0` — first public
release. 41 schema entries plus manifest, 49-action canonical response
catalog, 4 ratified RFCs, two reference implementations (Python
`warlog-spec` 0.1.0, TypeScript `@warlog/spec` 0.1.0) producing byte-
equivalent canonical output. The contract is open to community review
until v1.0 stable ; breaking changes between v0.1 and v0.2 are
explicitly allowed and welcome. We accept RFCs against it through the
process documented in [`rfcs/`](rfcs/).

## What is this

Warlog Spec is a language-agnostic, vendor-neutral contract for SOC workflow
artifacts:

- **Decision artifacts** — `TriageProposal`, `ClassificationAssessment`,
  `MitreAssessment`, `NextStepProposal`, `EnrichmentAssessment`,
  `PlaybookCandidateProposal`, `InvestigationSummaryProposal`,
  `ClosureSummary`, `CaseReturnSummary`, `RiskArbitration`,
  `ApprovalDecision`. These are the hashable artifacts referenced from
  `AuditRow.decision_ref`.
- **Provider ABI** — `ConnectorCapability`, `ResponseActionSpec`,
  `ResponseActionResult`, `AuditRow`, `SignedAuditRow`, `ConnectorError`,
  full auth + dry-run + audit + failure model.
- **Action catalog** — 49 canonical `ResponseActionId` values across 8
  families (identity, device, network, email, iam, key, storage,
  workflow) with reversibility classification and default approval
  level metadata.
- **Pack manifest** — distribution layer for detection rules, playbooks,
  KB articles, connectors.
- **Workflow enums** — Severity, Status, Verdict, Priority, Category, IOC
  type, Entity type/role, Confidence band, Review state.

UI projection shapes (TriageBundle / InvestigationBundle /
ResponseBundle / IncidentBundle) are deliberately **out of scope** —
they are product-specific UI surfaces, not interop contract.

Warlog Spec also does **not** publish the Warlog product runtime. The
public repository defines the contract that runtimes, connectors, and
agent wrappers can produce or consume. Warlog's L2M pipeline,
orchestration, policy engine, storage, queues, and console UX remain
part of the Warlog product. See [`docs/ADOPTION.md`](docs/ADOPTION.md)
for the public/private boundary and the shortest external-adopter path.

## Position vis-à-vis des standards existants

| Layer | Standard | Warlog Spec position |
|-------|----------|----------------------|
| Event schema | **OCSF** (Splunk/AWS/Cisco/...) | We **consume** OCSF events. Warlog Spec sits on top. |
| Threat intel | **STIX 2.1** (OASIS) | We **import** STIX bundles into IOC + KB artifacts. |
| Detection rules | **Sigma** (SigmaHQ) | We **compile** Sigma rules into a `DetectionRuleIR` representation (out of scope for v0.1, planned for a later RFC). |
| Response actions | **OpenC2** (OASIS) | We **map** to OpenC2 where pragmatic; we don't replace it. |
| Workflow / decisions | *(none)* | **This is what Warlog Spec defines.** |

## Why now

A workflow standard cannot emerge from a vendor that hasn't shipped the
product yet. It also cannot emerge from a vendor whose internal data
contract is still in dual-stack flux. Both conditions are now met or
imminently met for Warlog. The spec repo opens **before** the schemas are
finalized so the ecosystem (TheHive, OpenCTI, Wazuh, MSSPs, tier-2 SIEMs)
can shape the contract before lock-in.

## What's in here

```
warlog-spec/
├── README.md             ← you are here
├── VERSIONING.md         ← semver policy, additive vs breaking, deprecation
├── GOVERNANCE.md         ← BDFL → Technical Committee → foundation path
├── CONTRIBUTING.md       ← RFC process, CLA, review thresholds
├── COMPAT.md             ← matrix: spec version × provider implementation
├── THREAT-MODEL.md       ← what the spec protects against and what it does not
├── CHANGELOG.md          ← release notes
├── LICENSE               ← Apache 2.0
├── schemas/              ← 41 schema entries plus manifest — the contract
│   ├── manifest.json     ← index of all published schemas
│   ├── common/           ← 11 enum schemas
│   ├── action-params/    ← parameter schemas for selected response actions
│   ├── envelopes/        ← artifact + proposal envelopes
│   ├── artifacts/        ← classification, MITRE, enrichment, closure, case-return
│   ├── proposals/        ← triage, next-step, playbook-candidate, investigation-summary
│   ├── provider-abi/     ← connector-capability, response-action, audit-row, error
│   └── registry/         ← pack-manifest
├── examples/             ← canonical examples per artifact (round-trip-validated)
├── docs/                 ← quickstart, adoption, provider authoring, standards notes
├── registry/             ← static v0 registry preview (not hosted service)
├── rfcs/                 ← 4 ratified RFCs (trust-layer, AiAgentRef extensions,
│                            STIX projection, asymmetric signatures)
└── tests/conformance/    ← runner.py + negative corpus

../packages/                ← sibling reference implementations
├── warlog-spec-py/         ← Python package (Pydantic), 0.1.0 on PyPI
└── warlog-spec-ts/         ← TypeScript package (Zod), 0.1.0 on npm
```

## Where to find the schemas

The canonical JSON Schemas live in this directory under `schemas/`.
`schemas/manifest.json` is the authoritative index for the v0.1 release.
During the J-day release, the public mirror serves the same tree as
static files from GitHub Pages at the URL pattern :

```
https://3noP.github.io/warlog-spec/schemas/<version>/<subdir>/<name>.json
```

Versions :

- `draft` — current `main` branch, evolves freely until the first
  v1.0 release. Implementations targeting `draft` MUST tolerate
  breaking changes between commits.
- `v1.0` (forthcoming) — frozen at release. Once published, the
  URL `https://3noP.github.io/warlog-spec/schemas/v1.0/...` never
  changes. Subsequent v1.x MINOR releases live under their own URL
  (e.g. `/v1.1/`).

A consumer pinning to a stable version uses :

```
https://3noP.github.io/warlog-spec/schemas/v1.0/provider-abi/AuditRow.json
```

For v0.1, consumers should resolve schemas from the checkout, published
package bundle, or `schemas/manifest.json`. The remote GitHub Pages URLs
are release artifacts, not a second source of truth.

## Verifying conformance

Once you have an implementation, run the Level 1 (Read) check
against the canonical examples in `examples/` and the invalid corpus
under `tests/conformance/fixtures/invalid/` :

```
pip install jsonschema
python tests/conformance/runner.py --level 1
```

For Level 2 (Write), produce one fixture per productible type and
validate them all + verify coverage :

```
# If you are an adopter of warlog-spec-py, dump the reference fixtures :
python -m warlog_spec.conformance dump --out ./fixtures

# Then validate them via the runner (coverage check enforced) :
python tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
```

To validate a single artifact against a chosen schema :

```
python tests/conformance/runner.py \
    --json my-artifact.json \
    --schema proposals/triage-proposal.json
```

To claim conformance, open a PR against `COMPAT.md` with your
implementation row.

For the copy-paste path, start with [`docs/QUICKSTART.md`](docs/QUICKSTART.md).
For provider rules, see [`docs/PROVIDER-AUTHORING.md`](docs/PROVIDER-AUTHORING.md).
For the adoption model and static registry preview, see
[`docs/ADOPTION.md`](docs/ADOPTION.md).

## Ecosystem positioning

How Warlog Spec sits relative to the standards your stack already
speaks (OCSF, STIX 2.1, OpenC2, CACAO, OSCAL, Sigma, MITRE ATT&CK /
D3FEND / CAPEC / CWE) : see [`docs/ECOSYSTEM-MAPPING.md`](docs/ECOSYSTEM-MAPPING.md).

Short version : we **consume** OCSF and Sigma upstream, **translate**
to/from STIX and OpenC2, **complement** CACAO and OSCAL, and **embed**
MITRE identifiers verbatim. The trust layer (decision / signal /
compliance / AI-agent attribution on each audit row) is the only
surface that has no direct equivalent in the standards above —
that is what the spec actually introduces.

## Security and threat model

Warlog Spec is an **audit log primitive** for AI agent actions. It is not
a runtime sandbox, an EDR, a network policy engine, or a prevention layer
against hallucinated agent actions. Read [`THREAT-MODEL.md`](THREAT-MODEL.md)
before claiming a flaw : it enumerates nine adversary models (cold log
tampering, malicious insider, persistent root attacker, prompt injection,
compromised vendor, time tampering, framework-induced context loss,
in-memory PII exfiltration, replay / reordering), states what the spec
protects against and what it does not, and lists the operational
mitigations (external witness via S3 Object Lock, asymmetric signatures
per RFC 0004, vendor-side audit pairing, process memory hardening) that
turn the primitive into a production-grade audit stack.

The pattern itself is not novel : AWS CloudTrail Log File Integrity
Validation, Sigstore, Stripe Ledger, and Linux auditd all use variants
of the same chained-signature + external-witness approach. Warlog Spec
projects this established pattern onto the specific surface of AI agent
tool calls, with the cognitive-context binding (model, model version,
prompt hash, tools manifest hash) that EU AI Act Article 12 requires.

Standalone HMAC verification is exposed through both reference packages:

```sh
warlog-verify ./audit.jsonl --secret-file ./secret.bin
```

The command verifies JSONL exported by the reference persister or public
`SignedAuditRow` JSONL and reports the first row with a chain or
signature mismatch.

## RFCs

Changes to the spec go through a lightweight RFC process — see
[`rfcs/README.md`](rfcs/README.md) for numbering, status flow,
approval thresholds, and the document structure.

| Number | Title | Status |
|---|---|---|
| [0001](rfcs/0001-trust-layer.md) | Trust layer — decision / signal / compliance / AI-agent attribution on AuditRow | Accepted, Implemented |
| [0002](rfcs/0002-ai-agent-ref-extensions.md) | AiAgentRef extensions for multi-agent and tool-using compositions | Accepted, Implemented |
| [0003](rfcs/0003-stix-projection.md) | Outbound STIX 2.1 projection of CaseReturnSummary | Accepted, Implemented |
| [0004](rfcs/0004-asymmetric-signatures.md) | Asymmetric signatures (Ed25519, RSASSA-PSS) for AuditAttestation | Accepted, Schema Implemented |

## How to engage

This is the **first public release of an open spec at v0.1**. The
contract is stable enough that two reference implementations produce
byte-equivalent output against it, but v0.1 is explicitly experimental :
breaking changes between v0.1 and v0.2 are allowed during the public-
feedback window. We use plain `0.1.0` rather than `0.1.0rc1` because rc
implies "candidate for stable" — that is not the position of this
release. See [`VERSIONING.md`](VERSIONING.md) for the doctrine on what
triggers v1.0 stable (three external adopters validating it in their
stacks, plus the conditions documented there).

If you're an ecosystem partner (OSS project, MSSP, SIEM vendor,
integrator) and want to shape the contract before v1.0 :

- Open an issue on this repository for discussion.
- Submit an RFC via the process in [`rfcs/README.md`](rfcs/README.md)
  to propose an additive or breaking change.
- For private inquiries, contact the maintainer through the channels
  listed in [`GOVERNANCE.md`](GOVERNANCE.md).

## License

The spec — this directory's prose, JSON Schema files, and canonical
examples — is licensed under [Apache License 2.0](LICENSE). This matches
the conventions of OCSF and the OpenAPI Specification, and lets ecosystem
adopters embed schemas in their own projects without copyleft propagation.

The reference implementation libraries shipped alongside the spec
(`warlog-spec` for Python, `@warlog/spec`, and `@warlog/mcp-proxy`)
are also licensed under Apache 2.0 so third-party connector authors can
embed the contract primitives without copyleft friction. The full Warlog
runtime that consumes these packages remains licensed separately under
the parent project's AGPL3 + commercial dual model.

## Governance

Currently **BDFL** (Benevolent Dictator For Life — Warlog founder) for
spec evolution. Roadmap targets a community technical committee at v1.0
stable, and a foundation move (CNCF Sandbox / LF Cybersecurity) once
external adoption justifies it.

CLA required for external contributions — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
