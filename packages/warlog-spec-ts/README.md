# @warlog/spec

Warlog Spec — TypeScript reference implementation. The same contract
as the Python `warlog-spec` package : 18 productible artifact types,
Zod schemas for runtime validation, HMAC audit-chain primitives that
byte-equivalent the Python canonicalization.

## Why TypeScript

A spec implemented in one language is a library. A spec implemented
in two independent languages that produce byte-equivalent output is
a standard candidate. The TS package exists to prove the second
proposition.

## Install

```sh
npm install @warlog/spec
# or
pnpm add @warlog/spec
```

This is `v0.1.0` — the first public release. It is explicitly
experimental : breaking changes between v0.1 and v0.2 are allowed
during the public-feedback window. We do not use a `rc` suffix
because rc implies "candidate for stable" — that is not the position
of this release. See `CHANGELOG.md` for the doctrine.

## Usage

### Validating an audit row

```ts
import { AuditRow } from "@warlog/spec";

const row = AuditRow.parse(rawJson);
// row is fully typed: row.decisionRef.contentHash, row.actor.kind, etc.
```

### Producing a signed audit row

```ts
import {
  AuditRow,
  SignedAuditRow,
  canonicalizeV1,
  computeGenesis,
  computeSignature,
} from "@warlog/spec";

const secret = Buffer.from(process.env.WARLOG_HMAC_SECRET!, "utf-8");
const row = AuditRow.parse(rawJson);
const canonical = canonicalizeV1(row);
const prev = computeGenesis(row.tenantId, secret);
const signature = computeSignature(prev, canonical, secret);

const signed = SignedAuditRow.parse({
  payload: row,
  attestation: {
    prevRowHash: prev,
    signatureValue: signature,
    algorithm: "HMAC-SHA256",
    canonicalizationFormat: "v1",
    keyId: "tenant:T-001:hmac:v1",
  },
});
```

### Producing all 18 conformance fixtures

```ts
import { produceAll } from "@warlog/spec/conformance";

const examples = produceAll();
// {
//   "artifacts/approval-decision.json": { ... },
//   "artifacts/mitre-assessment.json": { ... },
//   ...
//   "registry/pack-manifest.json": { ... },
// }
```

Or use the packaged CLI after install :

```sh
npm exec --package @warlog/spec -- warlog-spec dump --out ./fixtures
```

## Conformance

Level 2 (Write) : `@warlog/spec` produces 18/18 productible canonical
types. Each factory output validates against the JSON Schema in
`warlog-spec/schemas/`. Validate it yourself :

```sh
git clone https://github.com/3noP/warlog-spec.git
cd warlog-spec/packages/warlog-spec-ts
npm install
npm test
npm run dump-fixtures
python ../../warlog-spec/tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
```

Level 4 (Provider) : the package emits a deterministic mock-vendor
provider report. The public runner validates the embedded ABI objects and
checks dry-run, apply, verify, idempotency replay, and unsupported-action
rejection:

```sh
node dist/cli.js provider-check --out ./provider-report.json
python ../../warlog-spec/tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
```

Cross-language byte equivalence is enforced by `tests/audit-chain.test.ts` :
the TS `canonicalizeV1` output for a pinned audit row matches the
Python canonicalization byte-for-byte. This is what makes a
`SignedAuditRow` verifiable regardless of which language signed it.

## Audit-chain verification

The package also ships the standalone verifier binary:

```sh
npm exec --package @warlog/spec -- warlog-verify ./audit.jsonl --secret-file ./secret.bin
# OK : 1247 rows, chain valid, no gaps, no tampering
```

It accepts newline-delimited `JsonlFilePersister` records or public
`SignedAuditRow` objects. The secret file is read as raw bytes; do not
add a trailing newline unless that newline is part of the signing secret.

## OCSF Detection Finding mapper

The package includes a conservative inbound mapper for OCSF Detection
Finding events:

```ts
import { mapOcsfDetectionFinding } from "@warlog/spec";

const mapped = mapOcsfDetectionFinding(ocsfEvent);
console.log(mapped.triggerSignal.contentHash);
console.log(mapped.classification.classification.severity);
```

It emits existing public shapes only: `TriggerSignalRef`,
`ClassificationAssessment`, `EnrichmentAssessment`, and optional
`MitreAssessment` from OCSF `attacks[]`. The original OCSF payload is
hashed with stable sorted-key JSON and referenced by `TriggerSignalRef`;
raw ingestion, alert persistence, deduplication, and routing remain the
operator/runtime's responsibility.

## Reference connectors

Two vendor-realistic reference connectors live under [`examples/`](https://github.com/3noP/warlog-spec/tree/main/packages/warlog-spec-ts/examples)
in the source repo. They are NOT shipped in the npm tarball — the
package exports the spec primitives (`AbiConnector`, the Zod schemas,
the audit-chain crypto), and the example files are meant to be copied
into your project as starting templates. Both use the built-in `fetch`
API, so they have no transport dependency on top of `@warlog/spec`.

### CrowdStrike Falcon (EDR)

[`examples/crowdstrike-falcon-connector.ts`](https://github.com/3noP/warlog-spec/blob/main/packages/warlog-spec-ts/examples/crowdstrike-falcon-connector.ts)
— covers 5 EDR actions (`host.isolate`, `host.unisolate`,
`host.collect_artifacts`, `file.quarantine`, `hash.block`), OAuth2
client_credentials auth with lazy bearer refresh, Falcon error
envelope mapping to `ConnectorAbiError` categories. Copy the file
into your project and instantiate it directly :

```ts
import { CrowdstrikeFalconConnector } from "./connectors/crowdstrike-falcon-connector.ts";

const connector = new CrowdstrikeFalconConnector({
  baseUrl: "https://api.us-2.crowdstrike.com",
  clientId: process.env.FALCON_CLIENT_ID!,
  clientSecret: process.env.FALCON_CLIENT_SECRET!,
});
```

### Okta identity (IAM)

[`examples/okta-user-response-connector.ts`](https://github.com/3noP/warlog-spec/blob/main/packages/warlog-spec-ts/examples/okta-user-response-connector.ts)
— covers 5 identity actions (`user.disable`, `user.force_logout`,
`user.reset_mfa`, `user.revoke_tokens`, `user.reset_password`),
SSWS API-token auth, and the GDPR pseudonymization gate via an
injected `resolveSubject` callback for hash → upn resolution.

```ts
import { OktaUserResponseConnector } from "./connectors/okta-user-response-connector.ts";

const connector = new OktaUserResponseConnector({
  baseUrl: "https://your-tenant.okta.com",
  apiToken: process.env.OKTA_API_TOKEN!,
  resolveSubject: async (hashedValue) => {
    // Production : look up the hash in your tenant-side vault.
    return vaultClient.resolveIdentity(hashedValue);
  },
});
```

## License

Apache 2.0. Same as `warlog-spec/` and `warlog-spec-py`.
