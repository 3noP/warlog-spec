# Conformance Tests

The public runner validates both sides of the contract:

- valid examples under `warlog-spec/examples/` MUST validate against their schemas
- invalid fixtures under `tests/conformance/fixtures/invalid/` MUST fail validation
- Level 2 implementation fixtures MUST cover every productible schema
- Level 4 provider reports MUST prove the mock-vendor ABI lifecycle

Run the read-side corpus:

```sh
python tests/conformance/runner.py --level 1
```

The negative corpus is intentionally hand-authored. Each file is named with
the same convention as positive examples, so
`fixtures/invalid/provider-abi/response-action-result.success-with-error.json`
targets `schemas/provider-abi/response-action-result.json`.

Add a negative fixture whenever a schema gets a new trust-boundary invariant,
especially around approval, provenance, hash references, pseudonymized
selectors, audit-chain links, and provider failure semantics.