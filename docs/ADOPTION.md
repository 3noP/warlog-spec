# Adoption Guide

Warlog Spec is the public contract, not the Warlog product runtime. It
defines the schemas, provider ABI, action catalog, audit-chain envelope,
and conformance rules that another tool can implement. The Warlog
product keeps its L2M pipeline, orchestration, policy engine, storage,
ranking, UI, and tenant operations private to the product.

The adoption target for v0.1 is deliberately small: an external team
should be able to validate the schemas, produce fixtures, and write a
minimal connector without importing the Warlog backend. For the shortest
copy-paste path, see `QUICKSTART.md`. For connector requirements, see
`PROVIDER-AUTHORING.md`.

## 15-minute path

1. Work from a checkout of this repo and install one reference package.

   ```sh
   git clone https://github.com/3noP/warlog-spec.git
   cd warlog-spec
   pip install warlog-spec[verify]
   # or, for TypeScript adopters
   npm install @warlog/spec
   ```

2. Validate the canonical examples and invalid corpus from the checkout.

   ```sh
   python tests/conformance/runner.py --level 1
   ```

3. Produce Level 2 fixtures.

   ```sh
   warlog-spec dump --out ./fixtures
   python tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
   ```

   In Python environments, `python -m warlog_spec.conformance dump --out
   ./fixtures` is equivalent to the `warlog-spec` console command.

4. Produce a Level 4 mock-provider report when you are working on the
   Provider ABI.

   ```sh
   warlog-spec provider-check --out ./provider-report.json
   python tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
   ```

   The report exercises a deterministic mock vendor. It proves Provider
   ABI lifecycle behavior; it does not claim live vendor validation.

5. Start from the smallest connector template.

   - Python: `packages/warlog-spec-py/examples/echo_connector.py`
   - TypeScript: `packages/warlog-spec-ts/examples/echo-connector.ts`

6. Open a PR against `COMPAT.md` once your implementation can reproduce
   its claimed level and scope.

## Conformance ladder

| Level | Meaning | Evidence |
|---|---|---|
| 1 | Read | Parses and validates canonical examples. |
| 2 | Write | Produces one conformant fixture per declared productible type. |
| 3 | Full | Supports read and write across its declared artifact scope. |
| 4 | Provider | Emits a mock-vendor report that proves Provider ABI lifecycle behavior, side-effect-free dry-run, idempotent apply, verify, and unsupported-action rejection. |
| 5 | Live validated | Level 4 plus documented validation against a real tenant or lab environment. |

Level 5 is intentionally not claimed by the v0.1 reference connectors.
Those connectors are written from public vendor documentation and tested
against contract/mocking surfaces. Live-tenant validation should be
claimed only by the operator who ran it.

## Provider-style ecosystem model

Warlog Spec borrows the useful part of the Terraform/HashiCorp pattern:
a stable provider contract, a conformance ladder, and a registry-preview
catalog that makes integration status visible. These levels are evidence
claims, not a certification program. The analogy stops there.
Warlog Spec does not standardize the Warlog runtime, SOC UI, L2M logic,
or playbook execution engine.

The v0.1 registry is static by design. See `registry/index.json` for the
machine-readable preview and `registry/README.md` for the policy. A
hosted registry API, signatures, and air-gapped import flow are future
work once external implementations exist.

## Public/private boundary

Public in this repository:

- JSON Schemas and canonical examples.
- Provider ABI and response action catalog.
- HMAC audit-chain envelope and verification primitives.
- Python and TypeScript reference libraries.
- Conformance runner, fixture producers, and mock-provider report checks.
- OCSF Detection Finding mapper into portable Warlog Spec artifacts.
- Minimal connector templates and vendor-realistic examples.

Private to the Warlog product/runtime:

- L2M generation pipeline and model orchestration.
- Policy/ranking engines and tenant-specific decision logic.
- Runtime persistence, UI projections, queues, and operator workflows.
- Live connector credentials, deployment topology, and tenant operations.