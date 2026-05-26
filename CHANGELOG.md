# Changelog

All notable changes to Warlog Spec are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
spec follows [Semantic Versioning](https://semver.org/). See
`VERSIONING.md` for the schema-specific versioning policy.

## [0.1.0] - 2026-05-26

First public release of Warlog Spec.

### Added
- Canonical JSON Schemas for the public contract, published under
  `schemas/` and indexed by `schemas/manifest.json`.
- Canonical examples under `examples/` for the contract surfaces shipped
  in this release.
- Public conformance assets under `tests/conformance/`, including the
  Level 1 validation runner, the invalid fixture corpus, and the
  reference Level 2 / Level 4 producer checks used by the reference
  packages.
- The canonical response action catalog and the published parameter
  schemas for the action families included in this release.
- Public governance, contribution, adoption, quickstart, provider
  authoring, threat model, and ecosystem-mapping documentation.
- Four accepted RFCs covering the trust layer, AI-agent reference
  extensions, STIX projection, and asymmetric signature support.
- Reference implementation packages shipped alongside the spec:
  - `warlog-spec` for Python
  - `@warlog/spec` for TypeScript
  - `@warlog/mcp-proxy` for the approval-gate proxy layer

### Included in this release
- 41 schema entries plus the manifest index.
- 49 canonical response actions across the published action families.
- Python and TypeScript reference implementations that produce
  equivalent canonical output for the shared contract surfaces.
- A public GitHub Pages deployment serving canonical schema `$id` URLs
  under `https://3noP.github.io/warlog-spec/schemas/...`.
- Public GitHub Actions workflows covering the Python package,
  TypeScript package, MCP proxy package, and Pages deployment.

### Notes
- `0.1.0` is the first public release and remains pre-`1.0`.
  Additive and breaking changes are still allowed under the policy
  described in `VERSIONING.md`.
- GitHub Pages is used as a static schema host for canonical URLs. The
  schema paths are the supported public surface; the site root is not a
  product homepage.

[0.1.0]: https://github.com/3noP/warlog-spec/releases/tag/v0.1.0
