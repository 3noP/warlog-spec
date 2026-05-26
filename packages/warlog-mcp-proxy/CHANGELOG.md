# Changelog

## [0.1.0] — 2026-05-21 — first public npm release

First artifact of `@warlog/mcp-proxy`. Released in lockstep with
`warlog-spec` (Python) 0.1.0 and `@warlog/spec` (TypeScript) 0.1.0.

### Added

- `warlog-mcp-proxy wrap` CLI : stdio JSON-RPC proxy that wraps any
  backend MCP server, intercepts `tools/call`, signs an `AuditRow` per
  call into a local HMAC chain, forwards transparently.
- YAML mapping file format : explicit MCP-tool-name → canonical Warlog
  `ResponseActionId` mapping. Fuzzy-matching deliberately not
  supported. Validated against the canonical 49-action catalog at
  startup.
- `JsonlAuditPersister` : append-only JSONL persister, recovers the
  head signature across process restarts.
- GDPR pseudonymization gate : subjects from PII families (identity /
  email / iam) are auto-hashed `sha256(salt || value)` with the
  configured `selector_key_id`. The salt is in-process — never
  persisted in the chain — which preserves the right-to-erasure-by-salt-
  rotation doctrine.
- Strict mode (`--strict`) : refuses unmapped tools with a JSON-RPC
  error so production deployments never sign with a guessed action_id.
- Sample configuration : `examples/okta-actions.yml` and
  `examples/claude-desktop-config.jsonc`.

### Conformance

- 14 vitest tests cover : mapping validation, persister round-trip,
  chain linkage, PII pseudonymization, strict-mode refusal,
  loose-mode forward-with-warning, restart-resume.
- AuditRow byte format identical to the Python and TypeScript
  reference implementations of `warlog-spec` — chains produced by the
  MCP proxy verify under the same canonical-bytes test suite.
