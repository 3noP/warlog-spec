# Quickstart

This is the shortest path for an external adopter. It validates the
public contract and produces fixtures without importing the Warlog
product runtime.

## Python

```sh
pip install warlog-spec[verify]
git clone https://github.com/3noP/warlog-spec.git
cd warlog-spec
python tests/conformance/runner.py --level 1
warlog-spec dump --out ./fixtures
python tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
warlog-spec provider-check --out ./provider-report.json
python tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
```

Expected result:

```text
9/9 examples validate against their schemas
7/7 invalid fixtures rejected by their schemas
Negative coverage : 5 schema surfaces represented
18/18 fixtures validate against their schemas
Coverage : 18/18 productible types represented
OK   Level 4 provider report: provider-report.json [...]
```

## TypeScript

```sh
git clone https://github.com/3noP/warlog-spec.git
cd warlog-spec/packages/warlog-spec-ts
npm install
npm test
npm run build
node dist/cli.js dump --out ./fixtures
python ../../warlog-spec/tests/conformance/runner.py --level 2 --fixtures-dir ./fixtures
node dist/cli.js provider-check --out ./provider-report.json
python ../../warlog-spec/tests/conformance/runner.py --level 4 --provider-report ./provider-report.json
```

After npm publication, the fixture step can also be run from a consumer
project with:

```sh
npm exec --package @warlog/spec -- warlog-spec dump --out ./fixtures
npm exec --package @warlog/spec -- warlog-spec provider-check --out ./provider-report.json
```

The provider report uses a deterministic mock vendor. It is suitable for
Level 4 Provider ABI evidence; live tenant or lab validation remains a
separate Level 5 claim.

## Verify An Audit Chain

Both reference packages expose a standalone HMAC audit-chain verifier.
It accepts JSONL exported by `JsonlFilePersister` or newline-delimited
`SignedAuditRow` objects.

```sh
warlog-verify ./audit.jsonl --secret-file ./secret.bin
# OK : 1247 rows, chain valid, no gaps, no tampering
```

The secret file is read as raw bytes. Do not add a trailing newline
unless that newline is part of the signing secret.

## Map An OCSF Detection Finding

The reference packages include a small inbound OCSF mapper. It converts a
Detection Finding into existing Warlog Spec artifacts plus a hashed
`TriggerSignalRef`.

```python
from warlog_spec import map_ocsf_detection_finding

mapped = map_ocsf_detection_finding(ocsf_event)
print(mapped.trigger_signal.content_hash)
print(mapped.classification.classification.severity)
```

```ts
import { mapOcsfDetectionFinding } from "@warlog/spec";

const mapped = mapOcsfDetectionFinding(ocsfEvent);
console.log(mapped.triggerSignal.contentHash);
console.log(mapped.classification.classification.severity);
```

The mapper covers `TriggerSignalRef`, `ClassificationAssessment`,
`EnrichmentAssessment`, and `MitreAssessment` when OCSF `attacks[]` is
present. Alert storage, correlation, queueing, and routing remain runtime
concerns.

## First Connector

Start with the smallest template, then replace the in-memory calls with
your vendor API calls.

- Python: `packages/warlog-spec-py/examples/echo_connector.py`
- TypeScript: `packages/warlog-spec-ts/examples/echo-connector.ts`

When your implementation can reproduce its claimed conformance level,
open a PR against `COMPAT.md` with the implementation name, version,
levels claimed, and validation date.