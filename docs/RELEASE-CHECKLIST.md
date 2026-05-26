# Release Checklist

Use this checklist before publishing `warlog-spec`, `@warlog/spec`, and
`@warlog/mcp-proxy`. It covers the public, reproducible quality gates.
Maintainer-only publishing steps that require private credentials are
handled separately.

## Preflight

- Confirm public docs do not describe unpublished artifacts as already
  published.
- Confirm reference connectors are described as contract-tested unless
  live-tenant evidence exists.
- Confirm `warlog-spec` is described as the public contract, not the
  Warlog runtime or L2M engine.
- Confirm package versions match across Python, TypeScript, MCP proxy,
  changelogs, and compatibility matrix.

## Python Package

```sh
cd packages/warlog-spec-py
python -m pip install -e .[test]
python -m pytest tests -q
warlog-spec dump --out ./fixtures
python ../../warlog-spec/tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
warlog-spec provider-check --out ./provider-report.json
python ../../warlog-spec/tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
python -m build --sdist --wheel
```

Expected: no warnings, the package test suite passes, `18/18 fixtures
validate`, Level 4 provider report validates, verifier CLI tests pass,
and wheel + sdist are produced.

## TypeScript Package

```sh
cd packages/warlog-spec-ts
npm install
npm test
npm run build
node dist/cli.js dump --out ./fixtures
python ../../warlog-spec/tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
node dist/cli.js provider-check --out ./provider-report.json
python ../../warlog-spec/tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
npm pack --dry-run
```

Expected: all Vitest tests pass, `dist/cli.js` is present, `18/18`
fixtures validate, Level 4 provider report validates, verifier CLI tests pass, and the npm tarball
contains `dist`, README, LICENSE, CHANGELOG, and package metadata.

## MCP Proxy

```sh
cd packages/warlog-mcp-proxy
npm install
npm test
npm run build
npm pack --dry-run
```

Before publishing `@warlog/mcp-proxy`, replace the local
`"@warlog/spec": "file:../warlog-spec-ts"` dependency with the
published `0.1.0` version, publish, then restore the local dependency in
the monorepo.

## Conformance Runner

```sh
python warlog-spec/tests/conformance/runner.py --level 1
```

Expected: `9/9 examples validate against their schemas` and `7/7
invalid fixtures rejected by their schemas`.

## Post-Publish Verification

- Install Python from PyPI in a clean environment and run `warlog-spec
  dump`.
- Install `@warlog/spec` in a clean Node project and run the packaged
  CLI.
- Install `@warlog/mcp-proxy` and verify the `warlog-mcp-proxy` binary
  starts with `--help`.
- Update `COMPAT.md` dates only after the public artifacts are actually
  available.